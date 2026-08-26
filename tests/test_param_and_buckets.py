"""Tests for param_fuzz, cloud_bucket_enum, and shared response_diff."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.parsers.registry import CloudBucketEnumParser, ParamFuzzParser
from core.response_diff import (
    ResponseSnapshot,
    bodies_near_identical,
    canary_reflected,
    significant_response_change,
)
from modules.cloud_bucket_enum import (
    CloudBucketEnumPlugin,
    _candidate_buckets,
    _classify,
)
from modules.param_fuzz import CANARY_VALUE, PARAM_WORDLIST, ParamFuzzPlugin
from utils.files import read_jsonl

_SCOPE = CollectionScope.from_seeds(
    ["example.com", "metaversejustice.com"], cloud_collection_allowed=True
)


def test_bodies_near_identical_and_significant_change() -> None:
    base = ResponseSnapshot(200, b"hello world" * 20)
    noisy = ResponseSnapshot(200, b"hello world" * 20 + b"x")
    assert bodies_near_identical(base.body, noisy.body)
    assert not significant_response_change(base, noisy)

    different = ResponseSnapshot(200, b"completely different body content here!!!!")
    assert significant_response_change(base, different)

    status_change = ResponseSnapshot(500, base.body)
    assert significant_response_change(base, status_change)


def test_canary_reflected() -> None:
    assert canary_reflected(b"foo reconprobe123 bar", "reconprobe123")
    assert not canary_reflected(b"nothing here", "reconprobe123")
    # Exact / case-sensitive — must not match a case-folded variant.
    assert not canary_reflected(b"ReconProbe123", "reconprobe123")


def test_reflected_context_captures_surrounding_excerpt() -> None:
    from core.response_diff import reflected_context

    body = (
        b"xxxxxxxx results for your search of <strong>reconprobe123</strong> "
        b"were not found yyyyyyyy"
    )
    excerpt = reflected_context(body, "reconprobe123", window=40)
    assert excerpt is not None
    assert "reconprobe123" in excerpt
    assert "search of" in excerpt or "strong" in excerpt
    # Change without the literal canary → no false context.
    assert reflected_context(b"totally different dynamic page", "reconprobe123") is None


@pytest.mark.asyncio
async def test_param_fuzz_detects_status_change_and_creates_finding(
    settings: Settings, tmp_path: Path
) -> None:
    settings.enable_param_fuzz = True
    settings.param_fuzz_delay_ms = 0
    settings.param_fuzz_max_urls_per_host = 1
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.alive_urls = ["https://example.com/"]
    context.httpx_results = [{"url": "https://example.com/"}]

    def fake_get(url: str, **kwargs):
        if "debug=" in url:
            return ResponseSnapshot(500, b"error debug mode")
        return ResponseSnapshot(200, b"ok homepage content here")

    with patch("modules.param_fuzz.http_get", side_effect=fake_get):
        # Shrink wordlist to keep the test fast
        with patch("modules.param_fuzz.PARAM_WORDLIST", ("id", "debug", "page")):
            plugin = ParamFuzzPlugin(settings)
            result = await plugin.run(context, output_dir / "alive.txt")

    assert result.success
    rows = read_jsonl(output_dir / "param_fuzz.jsonl")
    assert any(r["parameter"] == "debug" and r["parameter_influences_response"] for r in rows)
    assert (output_dir / "param_fuzz_raw" / "example.com.txt").exists()

    hosts, _ = ParamFuzzParser().parse(output_dir)
    assert hosts
    assert any(f.template_id == "param-influences-response" for f in hosts[0].findings)
    assert any(f.severity == "info" for f in hosts[0].findings)


@pytest.mark.asyncio
async def test_param_fuzz_marks_reflected_as_medium(settings: Settings, tmp_path: Path) -> None:
    settings.param_fuzz_delay_ms = 0
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.alive_urls = ["https://example.com/"]
    context.httpx_results = [{"url": "https://example.com/"}]

    def fake_get(url: str, **kwargs):
        if f"q={CANARY_VALUE}" in url:
            body = f"search results for {CANARY_VALUE}".encode()
            return ResponseSnapshot(200, body)
        return ResponseSnapshot(200, b"homepage without canary")

    with patch("modules.param_fuzz.http_get", side_effect=fake_get):
        with patch("modules.param_fuzz.PARAM_WORDLIST", ("q",)):
            await ParamFuzzPlugin(settings).run(context, output_dir / "alive.txt")

    rows = read_jsonl(output_dir / "param_fuzz.jsonl")
    assert rows[0]["reflected"] is True
    assert "reconprobe123" in str(rows[0].get("reflected_context") or "")
    raw = (output_dir / "param_fuzz_raw" / "example.com.txt").read_text(encoding="utf-8")
    assert "reflected_context:" in raw
    assert "reconprobe123" in raw
    hosts, _ = ParamFuzzParser().parse(output_dir)
    finding = hosts[0].findings[0]
    assert finding.template_id == "param-reflected"
    assert finding.severity == "medium"


@pytest.mark.asyncio
async def test_param_fuzz_influence_without_reflection_has_no_context(
    settings: Settings, tmp_path: Path
) -> None:
    """Body changed (status/hash) but canary string absent → no reflected_context."""
    settings.param_fuzz_delay_ms = 0
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.alive_urls = ["https://example.com/"]
    context.httpx_results = [{"url": "https://example.com/"}]

    def fake_get(url: str, **kwargs):
        if "debug=" in url:
            return ResponseSnapshot(500, b"internal error page without canary token")
        return ResponseSnapshot(200, b"ok homepage content here")

    with patch("modules.param_fuzz.http_get", side_effect=fake_get):
        with patch("modules.param_fuzz.PARAM_WORDLIST", ("debug",)):
            await ParamFuzzPlugin(settings).run(context, output_dir / "alive.txt")

    row = read_jsonl(output_dir / "param_fuzz.jsonl")[0]
    assert row["parameter_influences_response"] is True
    assert row["reflected"] is False
    assert "reflected_context" not in row
    raw = (output_dir / "param_fuzz_raw" / "example.com.txt").read_text(encoding="utf-8")
    assert "reflected_context:" not in raw


@pytest.mark.asyncio
async def test_param_fuzz_skips_host_when_baseline_rate_limited(
    settings: Settings, tmp_path: Path
) -> None:
    """Baseline 429 → no param probes; marked baseline_invalid, not clean 0 hits."""
    settings.param_fuzz_delay_ms = 0
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.alive_urls = ["https://example.com/"]
    context.httpx_results = [{"url": "https://example.com/"}]

    calls: list[str] = []

    def fake_get(url: str, **kwargs):
        calls.append(url)
        return ResponseSnapshot(429, b"<!DOCTYPE HTML><title>429 Too Many Requests</title>")

    with patch("modules.param_fuzz.http_get", side_effect=fake_get):
        with patch("modules.param_fuzz.PARAM_WORDLIST", ("id", "page", "s", "q")):
            result = await ParamFuzzPlugin(settings).run(context, output_dir / "alive.txt")

    assert result.success
    # Only the baseline request — never the wordlist.
    assert len(calls) == 1
    assert "id=" not in calls[0]

    rows = read_jsonl(output_dir / "param_fuzz.jsonl")
    assert len(rows) == 1
    assert rows[0]["baseline_invalid"] is True
    assert rows[0]["baseline_status"] == 429
    assert "429" in rows[0]["reason"]
    assert rows[0]["parameters_probed"] == 0

    invalid = context.metadata["param_fuzz_baseline_invalid_hosts"]
    assert len(invalid) == 1
    assert invalid[0]["host"] == "example.com"
    assert invalid[0]["baseline_invalid"] is True
    assert context.metadata["param_fuzz_hits"] == 0
    assert context.metadata["param_fuzz_urls_probed"] == 0
    assert "baseline blocked/rate-limited" in result.message
    assert any(
        "invalid baseline" in w.lower() or "rate-limited" in w.lower() for w in context.warnings
    )

    raw = (output_dir / "param_fuzz_raw" / "example.com.txt").read_text(encoding="utf-8")
    assert "BASELINE_INVALID" in raw
    assert ParamFuzzParser().parse(output_dir)[0] == []


@pytest.mark.asyncio
async def test_param_fuzz_raw_artifact_never_embeds_analyst_home(
    settings: Settings, tmp_path: Path
) -> None:
    """Shareable JSONL must store raw_artifact relative to the run output dir."""
    settings.param_fuzz_delay_ms = 0
    output_dir = tmp_path / "Users" / "testuser" / "secret-project" / "output" / "run1"
    output_dir.mkdir(parents=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.alive_urls = ["https://example.com/"]
    context.httpx_results = [{"url": "https://example.com/"}]

    def fake_get(url: str, **kwargs):
        if "debug=" in url:
            return ResponseSnapshot(500, b"error debug mode")
        return ResponseSnapshot(200, b"ok homepage content here")

    with patch("modules.param_fuzz.http_get", side_effect=fake_get):
        with patch("modules.param_fuzz.PARAM_WORDLIST", ("debug",)):
            await ParamFuzzPlugin(settings).run(context, output_dir / "alive.txt")

    blob = (output_dir / "param_fuzz.jsonl").read_text(encoding="utf-8")
    assert "/Users/testuser/secret-project" not in blob
    assert str(output_dir) not in blob
    row = read_jsonl(output_dir / "param_fuzz.jsonl")[0]
    assert row["raw_artifact"] == "param_fuzz_raw/example.com.txt"
    assert (output_dir / row["raw_artifact"]).exists()


@pytest.mark.asyncio
async def test_param_fuzz_continues_when_baseline_ok(settings: Settings, tmp_path: Path) -> None:
    """Baseline 200 → wordlist probes run as before."""
    settings.param_fuzz_delay_ms = 0
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.alive_urls = ["https://example.com/"]
    context.httpx_results = [{"url": "https://example.com/"}]

    calls: list[str] = []

    def fake_get(url: str, **kwargs):
        calls.append(url)
        if "debug=" in url:
            return ResponseSnapshot(500, b"error debug mode")
        return ResponseSnapshot(200, b"ok homepage content here")

    with patch("modules.param_fuzz.http_get", side_effect=fake_get):
        with patch("modules.param_fuzz.PARAM_WORDLIST", ("id", "debug")):
            result = await ParamFuzzPlugin(settings).run(context, output_dir / "alive.txt")

    assert result.success
    assert len(calls) == 3  # baseline + id + debug
    assert context.metadata["param_fuzz_baseline_invalid_hosts"] == []
    assert context.metadata["param_fuzz_urls_probed"] == 1
    assert "baseline blocked" not in result.message
    rows = read_jsonl(output_dir / "param_fuzz.jsonl")
    assert any(r.get("parameter") == "debug" for r in rows)
    assert not any(r.get("baseline_invalid") for r in rows)


def test_baseline_invalid_reason_codes() -> None:
    from modules.param_fuzz import _baseline_invalid_reason

    assert _baseline_invalid_reason(ResponseSnapshot(200, b"ok")) is None
    assert _baseline_invalid_reason(ResponseSnapshot(301, b"")) is None
    reason_429 = _baseline_invalid_reason(ResponseSnapshot(429, b"nope"))
    assert reason_429 is not None and "429" in reason_429
    reason_403 = _baseline_invalid_reason(ResponseSnapshot(403, b"nope"))
    assert reason_403 is not None and "403" in reason_403
    reason_err = _baseline_invalid_reason(ResponseSnapshot(None, b"", error="timeout"))
    assert reason_err is not None and "failed" in reason_err


@pytest.mark.asyncio
async def test_param_fuzz_no_noise_when_unchanged(settings: Settings, tmp_path: Path) -> None:
    settings.param_fuzz_delay_ms = 0
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.alive_urls = ["https://example.com/"]
    context.httpx_results = [{"url": "https://example.com/"}]

    with patch(
        "modules.param_fuzz.http_get",
        return_value=ResponseSnapshot(200, b"stable body content"),
    ):
        with patch("modules.param_fuzz.PARAM_WORDLIST", ("id", "page")):
            await ParamFuzzPlugin(settings).run(context, output_dir / "alive.txt")

    assert read_jsonl(output_dir / "param_fuzz.jsonl") == []
    hosts, _ = ParamFuzzParser().parse(output_dir)
    assert hosts == []


def test_param_wordlist_is_curated_not_tiny() -> None:
    assert 80 <= len(PARAM_WORDLIST) <= 150


def test_bucket_candidates_include_suffixes() -> None:
    names = _candidate_buckets(["metaversejustice"])
    assert "metaversejustice" in names
    assert "metaversejustice-backup" in names
    assert "metaversejustice.backup" in names
    assert "metaversejustice-staging" in names


def test_classify_s3_variants() -> None:
    assert (
        _classify(
            "s3",
            ResponseSnapshot(404, b"<Error><Code>NoSuchBucket</Code></Error>"),
        )
        == "not_found"
    )
    assert (
        _classify(
            "s3",
            ResponseSnapshot(403, b"<Error><Code>AccessDenied</Code></Error>"),
        )
        == "exists_private"
    )
    listing = (
        b'<?xml version="1.0"?><ListBucketResult>'
        b"<Contents><Key>a.txt</Key></Contents></ListBucketResult>"
    )
    assert _classify("s3", ResponseSnapshot(200, listing)) == "public_listable"


@pytest.mark.asyncio
async def test_cloud_bucket_enum_reports_private_and_public(
    settings: Settings, tmp_path: Path
) -> None:
    settings.cloud_bucket_enum_delay_ms = 0
    settings.cloud_bucket_enum_authorize_derived = True
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.targets = [DomainTarget(domain="metaversejustice.com")]

    def fake_get(url: str, **kwargs):
        # Canary names always not found
        if "reconprobe" in url:
            return ResponseSnapshot(404, b"<Code>NoSuchBucket</Code>")
        if "metaversejustice-backup" in url and "s3.amazonaws.com" in url:
            return ResponseSnapshot(403, b"<Code>AccessDenied</Code>")
        if "metaversejustice-assets" in url and "s3.amazonaws.com" in url:
            return ResponseSnapshot(
                200,
                b"<ListBucketResult><Contents><Key>x</Key></Contents></ListBucketResult>",
            )
        return ResponseSnapshot(404, b"<Code>NoSuchBucket</Code>")

    with patch("modules.cloud_bucket_enum.http_get", side_effect=fake_get):
        # Limit candidates to speed up
        with patch(
            "modules.cloud_bucket_enum._candidate_buckets",
            return_value=[
                "metaversejustice-backup",
                "metaversejustice-assets",
                "metaversejustice-nope",
            ],
        ):
            result = await CloudBucketEnumPlugin(settings).run(context, output_dir / "targets.txt")

    assert result.success
    rows = read_jsonl(output_dir / "cloud_bucket_enum.jsonl")
    classes = {(r["bucket"], r["classification"]) for r in rows}
    assert ("metaversejustice-backup", "exists_private") in classes
    assert ("metaversejustice-assets", "public_listable") in classes
    assert not any(r["bucket"] == "metaversejustice-nope" for r in rows)
    assert (output_dir / "cloud_bucket_enum_raw.txt").exists()

    hosts, _ = CloudBucketEnumParser().parse(output_dir)
    severities = {f.severity for h in hosts for f in h.findings}
    templates = {f.template_id for h in hosts for f in h.findings}
    assert "info" in severities
    assert "high" in severities
    assert "cloud-bucket-exists-private" in templates
    assert "cloud-bucket-public-listable" in templates


@pytest.mark.asyncio
async def test_cloud_bucket_enum_dns_failure_warning_for_s3(
    settings: Settings, tmp_path: Path
) -> None:
    settings.cloud_bucket_enum_delay_ms = 0
    settings.cloud_bucket_enum_authorize_derived = True
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.targets = [DomainTarget(domain="example.com")]

    def fake_get(url: str, **kwargs):
        if "s3.amazonaws.com" in url and "reconprobe" in url:
            return ResponseSnapshot(
                None,
                b"",
                error="<urlopen error [Errno 8] nodename nor servname provided, or not known>",
            )
        if "storage.googleapis.com" in url and "reconprobe" in url:
            return ResponseSnapshot(404, b"<Code>NoSuchBucket</Code>")
        if "blob.core.windows.net" in url and "reconprobe" in url:
            return ResponseSnapshot(
                None,
                b"",
                error="<urlopen error [Errno 8] nodename nor servname provided, or not known>",
            )
        return ResponseSnapshot(404, b"<Code>NoSuchBucket</Code>")

    with patch("modules.cloud_bucket_enum.http_get", side_effect=fake_get):
        with patch(
            "modules.cloud_bucket_enum._candidate_buckets",
            return_value=["example-backup"],
        ):
            await CloudBucketEnumPlugin(settings).run(context, output_dir / "t.txt")

    warnings = " ".join(context.warnings)
    assert "DNS resolution failure" in warnings
    assert "s3" in warnings.lower()
    # Azure NXDOMAIN on canary is expected — must NOT raise the S3-style DNS scare.
    assert not any(
        "canary against azure" in w.lower() and "DNS resolution" in w for w in context.warnings
    )


@pytest.mark.asyncio
async def test_cloud_bucket_enum_nosuchbucket_silent(settings: Settings, tmp_path: Path) -> None:
    settings.cloud_bucket_enum_delay_ms = 0
    settings.cloud_bucket_enum_authorize_derived = True
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    context = PipelineContext(output_dir=output_dir, collection_scope=_SCOPE)
    context.targets = [DomainTarget(domain="example.com")]

    with patch(
        "modules.cloud_bucket_enum.http_get",
        return_value=ResponseSnapshot(404, b"<Code>NoSuchBucket</Code>"),
    ):
        with patch(
            "modules.cloud_bucket_enum._candidate_buckets",
            return_value=["example-backup"],
        ):
            await CloudBucketEnumPlugin(settings).run(context, output_dir / "t.txt")

    assert read_jsonl(output_dir / "cloud_bucket_enum.jsonl") == []
    assert CloudBucketEnumParser().parse(output_dir)[0] == []

"""core/verification/preflight.py — hash/fingerprint helpers and the
historical cross-run check (design Part B.1).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from config.settings import Settings
from core.assets import ScanRun
from core.runner import PipelineRunner
from core.store import AssetStore
from core.verification.model import ContradictionSeverity
from core.verification.preflight import (
    compute_attribution_fingerprint,
    compute_scope_file_hash,
    historical_cross_check,
    scope_exclusion_canary_check,
    validate_webhook_url,
)


class TestComputeScopeFileHash:
    def test_none_scope_file_returns_none(self) -> None:
        assert compute_scope_file_hash(None) is None

    def test_missing_scope_file_returns_none(self, tmp_path: Path) -> None:
        assert compute_scope_file_hash(tmp_path / "does-not-exist.txt") is None

    def test_same_content_same_hash(self, tmp_path: Path) -> None:
        f1 = tmp_path / "scope1.txt"
        f2 = tmp_path / "scope2.txt"
        f1.write_text("*.example.com\n", encoding="utf-8")
        f2.write_text("*.example.com\n", encoding="utf-8")
        assert compute_scope_file_hash(f1) == compute_scope_file_hash(f2)

    def test_different_content_different_hash(self, tmp_path: Path) -> None:
        f1 = tmp_path / "scope1.txt"
        f2 = tmp_path / "scope2.txt"
        f1.write_text("*.example.com\n", encoding="utf-8")
        f2.write_text("*.other.com\n", encoding="utf-8")
        assert compute_scope_file_hash(f1) != compute_scope_file_hash(f2)

    def test_never_leaks_raw_content(self, tmp_path: Path) -> None:
        f1 = tmp_path / "scope1.txt"
        f1.write_text("supersecretprogram.example.com\n", encoding="utf-8")
        digest = compute_scope_file_hash(f1)
        assert digest is not None
        assert "supersecretprogram" not in digest


class TestComputeAttributionFingerprint:
    def test_nothing_configured_returns_none(self) -> None:
        assert compute_attribution_fingerprint(None, None) is None
        assert compute_attribution_fingerprint({}, None) is None

    def test_never_leaks_raw_header_value(self) -> None:
        fp = compute_attribution_fingerprint(
            {"X-HackerOne-Research": "my_h1_handle"}, "bugcrowd; cosmiccashew"
        )
        assert fp is not None
        assert "my_h1_handle" not in fp
        assert "cosmiccashew" not in fp

    def test_same_pair_same_fingerprint(self) -> None:
        a = compute_attribution_fingerprint({"X-H1": "handle"}, "ua")
        b = compute_attribution_fingerprint({"X-H1": "handle"}, "ua")
        assert a == b

    def test_different_program_different_fingerprint(self) -> None:
        """The exact item-7 shape: Stripchat's header vs. Glassdoor's."""
        stripchat = compute_attribution_fingerprint(
            {"X-HackerOne-Research": "stripchat_handle"}, None
        )
        glassdoor = compute_attribution_fingerprint(
            {"X-HackerOne-Research": "glassdoor_handle"}, None
        )
        assert stripchat != glassdoor


def _run(store: AssetStore, run_id: str, **kwargs) -> None:
    store.create_run(
        ScanRun(
            run_id=run_id,
            started_at="2026-01-01T00:00:00Z",
            targets=kwargs.pop("targets", ["stripchat.com"]),
            program_name=kwargs.pop("program_name", "Stripchat"),
            **kwargs,
        )
    )
    store.finish_run(run_id, host_count=0, alive_count=0, warnings=[], errors=[])


class TestHistoricalCrossCheck:
    def test_first_run_for_program_has_nothing_to_compare(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash="sha256:abc",
            attribution_fingerprint="sha256:def",
            current_scope_domains=["stripchat.com"],
        )
        assert findings == []

    def test_no_program_name_is_a_noop(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        _run(store, "r1")
        findings = historical_cross_check(
            store,
            program_name="",
            scope_file_hash="sha256:abc",
            attribution_fingerprint=None,
            current_scope_domains=["stripchat.com"],
        )
        assert findings == []

    def test_consistent_history_raises_nothing(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        _run(
            store,
            "r1",
            scope_file_hash="sha256:abc",
            attribution_fingerprint="sha256:def",
            targets=["stripchat.com"],
        )
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash="sha256:abc",
            attribution_fingerprint="sha256:def",
            current_scope_domains=["stripchat.com"],
        )
        assert findings == []

    def test_attribution_fingerprint_mismatch_is_flagged(self, tmp_path: Path) -> None:
        """The exact catalog item 7 shape: a Stripchat-flavored .env
        (attribution fingerprint from a prior Stripchat run) run again
        under PROGRAM_NAME=Stripchat but with a DIFFERENT header/UA in
        effect than history shows for that program."""
        store = AssetStore(tmp_path / "recon.db")
        _run(
            store,
            "stripchat-run-1",
            attribution_fingerprint=compute_attribution_fingerprint(
                {"X-HackerOne-Research": "stripchat_handle"}, None
            ),
            targets=["stripchat.com"],
        )
        current_fp = compute_attribution_fingerprint(
            {"X-HackerOne-Research": "glassdoor_handle"}, None
        )
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash=None,
            attribution_fingerprint=current_fp,
            current_scope_domains=["stripchat.com"],
        )
        assert len(findings) == 1
        assert findings[0].severity is ContradictionSeverity.DOWNGRADES_CONFIDENCE
        assert findings[0].related_table == "runs"
        assert findings[0].related_id == "stripchat-run-1"

    def test_scope_file_hash_mismatch_is_flagged(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        _run(store, "r1", scope_file_hash="sha256:old", targets=["stripchat.com"])
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash="sha256:new",
            attribution_fingerprint=None,
            current_scope_domains=["stripchat.com"],
        )
        assert len(findings) == 1
        assert findings[0].detector == "historical_cross_check_scope_file"

    def test_no_target_overlap_is_flagged(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        _run(store, "r1", targets=["stripchat.com"])
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash=None,
            attribution_fingerprint=None,
            current_scope_domains=["glassdoor.com"],
        )
        assert len(findings) == 1
        assert findings[0].detector == "historical_cross_check_target_overlap"

    def test_all_three_mismatches_produce_three_findings(self, tmp_path: Path) -> None:
        store = AssetStore(tmp_path / "recon.db")
        _run(
            store,
            "r1",
            scope_file_hash="sha256:old",
            attribution_fingerprint="sha256:old-attr",
            targets=["stripchat.com"],
        )
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash="sha256:new",
            attribution_fingerprint="sha256:new-attr",
            current_scope_domains=["glassdoor.com"],
        )
        assert len(findings) == 3
        assert all(f.severity is ContradictionSeverity.DOWNGRADES_CONFIDENCE for f in findings)

    def test_none_current_hash_never_flags_missing_history_value(self, tmp_path: Path) -> None:
        """A current hash of None (e.g. no SCOPE_FILE this run) must not be
        compared against a real historical hash — that is "no value", not
        "a different value"."""
        store = AssetStore(tmp_path / "recon.db")
        _run(store, "r1", scope_file_hash="sha256:old", targets=["stripchat.com"])
        findings = historical_cross_check(
            store,
            program_name="Stripchat",
            scope_file_hash=None,
            attribution_fingerprint=None,
            current_scope_domains=["stripchat.com"],
        )
        assert findings == []


class TestHistoricalCrossCheckWiredIntoRunner:
    """core/runner.py::PipelineRunner.run() actually calls
    historical_cross_check and persists the result — not just that the
    function works in isolation.

    A crashed run (missing tools) never reaches `store.finish_run()`
    (that call sits deep in the normal successful-completion path,
    core/runner.py near `_finalize_to_store`) — confirmed while writing
    this test, an earlier draft ran BOTH runs through the real, crashing
    `PipelineRunner.run()` and got zero flags every time, because the
    first "prior" run was never eligible for
    `find_latest_finished_run_for_program` (it requires `finished_at` to
    be set). Fixed by seeding the prior run directly via the store — the
    same way `TestHistoricalCrossCheck` above does — and only driving the
    run actually under test (the second one) through the real,
    missing-tools-aborted `PipelineRunner.run()`, mirroring
    tests/test_runner.py::test_handles_missing_tools_gracefully's pattern
    to keep this fast and hermetic while still exercising the real
    pre-flight wiring inside `run()`.
    """

    @pytest.mark.asyncio
    async def test_stripchat_attribution_header_reused_for_a_different_program(
        self, project_root: Path
    ) -> None:
        """Catalog item 7: a prior finished run under PROGRAM_NAME=Stripchat
        with one attribution header, then a new run under the SAME stale
        PROGRAM_NAME but a DIFFERENT header in effect — the real mechanism
        this whole design exists to catch."""
        db_path = project_root / "output" / "recon.db"
        store = AssetStore(db_path)
        store.create_run(
            ScanRun(
                run_id="stripchat-run-1",
                started_at="2026-01-01T00:00:00Z",
                targets=["stripchat.com"],
                program_name="Stripchat",
                attribution_fingerprint=compute_attribution_fingerprint(
                    {"X-HackerOne-Research": "my_stripchat_handle"}, None
                ),
            )
        )
        store.finish_run("stripchat-run-1", host_count=0, alive_count=0, warnings=[], errors=[])

        glassdoor_settings = Settings(
            project_root=project_root,
            program_name="Stripchat",  # stale PROGRAM_NAME, matching the real incident
            researcher_attribution_header={"X-HackerOne-Research": "my_glassdoor_handle"},
        )
        runner2 = PipelineRunner(glassdoor_settings)
        with patch.object(
            runner2.tool_manager, "validate_tools", new=AsyncMock(return_value=False)
        ):
            with patch.object(
                runner2.tool_manager,
                "ensure_mandatory_tools",
                new=AsyncMock(side_effect=Exception("tools missing")),
            ):
                context2 = await runner2.run(domain="stripchat.com", run_id="run2")

        flags = store.get_verification_flags("run2")
        assert len(flags) == 1
        assert flags[0]["detector"] == "historical_cross_check_attribution"
        assert flags[0]["related_id"] == "stripchat-run-1"
        assert any("Verification (pre-flight)" in w for w in context2.warnings)

    @pytest.mark.asyncio
    async def test_clean_repeat_run_raises_no_false_flags(self, project_root: Path) -> None:
        """Same program, same attribution, same target as the seeded prior
        run — zero noise, same standard as every other detector in this
        design."""
        db_path = project_root / "output" / "recon.db"
        store = AssetStore(db_path)
        store.create_run(
            ScanRun(
                run_id="stripchat-run-1",
                started_at="2026-01-01T00:00:00Z",
                targets=["stripchat.com"],
                program_name="Stripchat",
                attribution_fingerprint=compute_attribution_fingerprint(
                    {"X-HackerOne-Research": "my_stripchat_handle"}, None
                ),
            )
        )
        store.finish_run("stripchat-run-1", host_count=0, alive_count=0, warnings=[], errors=[])

        settings2 = Settings(
            project_root=project_root,
            program_name="Stripchat",
            researcher_attribution_header={"X-HackerOne-Research": "my_stripchat_handle"},
        )
        runner2 = PipelineRunner(settings2)
        with patch.object(
            runner2.tool_manager, "validate_tools", new=AsyncMock(return_value=False)
        ):
            with patch.object(
                runner2.tool_manager,
                "ensure_mandatory_tools",
                new=AsyncMock(side_effect=Exception("tools missing")),
            ):
                context2 = await runner2.run(domain="stripchat.com", run_id="run2")

        assert store.get_verification_flags("run2") == []
        assert not any("Verification (pre-flight)" in w for w in context2.warnings)


class TestValidateWebhookUrl:
    def test_empty_value_returns_none(self) -> None:
        assert validate_webhook_url("") is None
        assert validate_webhook_url("   ") is None

    def test_valid_https_url_is_accepted(self) -> None:
        url = "https://hooks.slack.com/services/ABC/DEF/ghijkl"
        assert validate_webhook_url(url) == url

    def test_valid_http_url_is_accepted(self) -> None:
        url = "http://localhost:9000/webhook"
        assert validate_webhook_url(url) == url

    def test_trailing_text_after_a_space_is_rejected(self) -> None:
        """The exact real corruption shape, confirmed empirically against
        this project's actual .env parser (python-dotenv): an UNQUOTED
        WEBHOOK_URL with a stray space and trailing text gets absorbed by
        dotenv into one string. urlparse alone silently accepts this
        (the trailing text becomes part of the path) — this check is what
        actually catches it."""
        with pytest.raises(Exception, match="WEBHOOK_URL"):
            validate_webhook_url("https://hooks.slack.com/services/ABC typo")

    def test_urlparse_alone_would_not_have_caught_this(self) -> None:
        """Documents exactly why the whitespace check is load-bearing, not
        redundant with urlparse's own validation."""
        from urllib.parse import urlparse

        parsed = urlparse("https://hooks.slack.com/services/ABC typo")
        assert parsed.scheme == "https"
        assert parsed.netloc == "hooks.slack.com"  # would pass a scheme/netloc-only check

    def test_missing_scheme_is_rejected(self) -> None:
        with pytest.raises(Exception, match="WEBHOOK_URL"):
            validate_webhook_url("hooks.slack.com/services/ABC")

    def test_non_http_scheme_is_rejected(self) -> None:
        with pytest.raises(Exception, match="WEBHOOK_URL"):
            validate_webhook_url("ftp://hooks.slack.com/services/ABC")


class TestScopeExclusionCanaryCheck:
    """The deliberately hardest check, saved for last (design Section 5
    step 6): actively probes Hydra's own authorize_active_indicator with a
    synthetic name shaped like each configured exclusion — never a real
    target.
    """

    def test_real_stripchat_wildcard_host_exclusion_now_works(self) -> None:
        """The exact real incident (catalog item 5): `!mta*.stripchat.com`
        that once protected nothing at all — `scope_exclusion_canary_check`
        used to flag this scope with an INVALIDATES finding (see git
        history of this test) because `host_fully_excluded` never treated a
        `*` inside an exclusion's host as a wildcard. Fixed in
        `core/scope.py::hostname_matches_pattern`
        (fix/scope-host-wildcard-exclusion-v2) — this is the same canary
        check the design doc's own acceptance test for that fix uses,
        confirming it now finds nothing wrong."""
        from core.intel.scope import CollectionScope

        scope = CollectionScope.from_seeds(
            ["stripchat.com"], patterns=["*.stripchat.com", "!mta*.stripchat.com"]
        )
        findings = scope_exclusion_canary_check(scope)
        assert findings == []

    def test_whole_domain_exclusion_that_works_raises_nothing(self) -> None:
        """!community.linktr.ee has no wildcard — host_fully_excluded
        already handles it correctly on this branch, so the canary must
        find zero problems."""
        from core.intel.scope import CollectionScope

        scope = CollectionScope.from_seeds(
            ["linktr.ee"], patterns=["*.linktr.ee", "!community.linktr.ee"]
        )
        findings = scope_exclusion_canary_check(scope)
        assert findings == []

    def test_path_specific_exclusion_that_works_raises_nothing(self) -> None:
        """!bancoplata.mx/*/whistleblowing — the original, long-established
        path-exclusion fix — must also raise nothing."""
        from core.intel.scope import CollectionScope

        scope = CollectionScope.from_seeds(
            ["bancoplata.mx"],
            patterns=["*.bancoplata.mx", "!bancoplata.mx/*/whistleblowing"],
        )
        findings = scope_exclusion_canary_check(scope)
        assert findings == []

    def test_no_exclusions_at_all_raises_nothing(self) -> None:
        from core.intel.scope import CollectionScope

        scope = CollectionScope.from_seeds(["example.com"], patterns=["*.example.com"])
        assert scope_exclusion_canary_check(scope) == []

    def test_never_makes_a_real_network_request(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Design Part D: the only network-adjacent exception in this whole
        package must still never touch a real socket — confirmed by
        failing the test if anything tries to resolve DNS or open a
        connection during the check."""
        from core.intel.scope import CollectionScope

        def _fail(*_args, **_kwargs):
            raise AssertionError("scope_exclusion_canary_check must never touch the network")

        monkeypatch.setattr("socket.socket.connect", _fail)
        monkeypatch.setattr("socket.getaddrinfo", _fail)

        scope = CollectionScope.from_seeds(
            ["stripchat.com"], patterns=["*.stripchat.com", "!mta*.stripchat.com"]
        )
        scope_exclusion_canary_check(scope)  # must not raise the monkeypatched AssertionError


class TestScopeExclusionCanaryCheckWiredIntoRunner:
    @pytest.mark.asyncio
    async def test_fixed_wildcard_exclusion_raises_no_flag_during_a_real_run(
        self, project_root: Path
    ) -> None:
        """End-to-end: a SCOPE_FILE with the once-broken `!mta*.stripchat.com`
        pattern now produces zero `verification_flags` rows and zero
        pre-flight warnings during a real (missing-tools-aborted)
        `PipelineRunner.run()` — `core/scope.py::hostname_matches_pattern`
        (fix/scope-host-wildcard-exclusion-v2) makes the exclusion actually
        take effect, so the canary check run inline as part of the real run
        has nothing left to report."""
        scope_path = project_root / "scope.txt"
        scope_path.write_text("*.stripchat.com\n!mta*.stripchat.com\n", encoding="utf-8")
        settings = Settings(project_root=project_root, scope_file=scope_path)
        runner = PipelineRunner(settings)
        with patch.object(runner.tool_manager, "validate_tools", new=AsyncMock(return_value=False)):
            with patch.object(
                runner.tool_manager,
                "ensure_mandatory_tools",
                new=AsyncMock(side_effect=Exception("tools missing")),
            ):
                context = await runner.run(domain="stripchat.com", run_id="run1")

        store = AssetStore(project_root / "output" / "recon.db")
        flags = store.get_verification_flags("run1")
        canary_flags = [f for f in flags if f["detector"] == "scope_exclusion_canary_check"]
        assert canary_flags == []
        assert not any("scope_exclusion_canary_check" in w for w in context.warnings)

"""Conservative-by-default posture for a run targeting a non-owned domain.

`core/external_mode.py` is pure logic (no I/O, no terminal prompt) so it can
be unit-tested directly — the actual `input()` confirmation lives in
`app.py`, which this file does not exercise.
"""

from __future__ import annotations

from pathlib import Path

from config.settings import Settings
from core.external_mode import (
    EXTERNAL_MODE_GATED_FLAGS,
    classify_run,
    format_scope_summary,
)
from core.intel.scope import CollectionScope


def _settings(**kwargs: object) -> Settings:
    return Settings(project_root=Path("/tmp"), **kwargs)


def test_classify_run_owned_domain_is_not_external() -> None:
    settings = _settings(owned_domains=("metaversejustice.com",))
    assert classify_run(["metaversejustice.com"], settings) is False


def test_classify_run_subdomain_of_owned_root_is_not_external() -> None:
    settings = _settings(owned_domains=("metaversejustice.com",))
    assert classify_run(["app.metaversejustice.com"], settings) is False


def test_classify_run_non_owned_domain_is_external() -> None:
    settings = _settings(owned_domains=("metaversejustice.com",))
    assert classify_run(["bancoplata.mx"], settings) is True


def test_classify_run_mixed_owned_and_non_owned_is_external() -> None:
    """Caution wins: one non-owned domain in the batch makes the whole run
    external, rather than silently running some targets unprotected."""
    settings = _settings(owned_domains=("metaversejustice.com",))
    assert classify_run(["metaversejustice.com", "bancoplata.mx"], settings) is True


def test_classify_run_no_owned_domains_declared_is_external() -> None:
    """OWNED_DOMAINS names what's exempt — nothing declared means nothing is
    assumed owned, not the reverse."""
    settings = _settings()
    assert classify_run(["metaversejustice.com"], settings) is True


def test_classify_run_forced_external_mode_short_circuits() -> None:
    settings = _settings(owned_domains=("metaversejustice.com",), external_target_mode=True)
    assert classify_run(["metaversejustice.com"], settings) is True


def test_apply_external_target_mode_defaults_lowers_rate_limits() -> None:
    settings = _settings()
    changes = settings.apply_external_target_mode_defaults()
    assert settings.external_target_mode is True
    assert settings.rate_limit == Settings.EXTERNAL_MODE_RATE_LIMIT
    assert settings.param_fuzz_delay_ms == Settings.EXTERNAL_MODE_PARAM_FUZZ_DELAY_MS
    assert settings.cloud_bucket_enum_delay_ms == Settings.EXTERNAL_MODE_CLOUD_BUCKET_ENUM_DELAY_MS
    assert len(changes) == 3


def test_apply_external_target_mode_defaults_never_clobbers_explicit_override() -> None:
    """An operator who already set a custom rate limit gets their value
    respected, not silently replaced by the conservative default."""
    settings = _settings(rate_limit=5)
    changes = settings.apply_external_target_mode_defaults()
    assert settings.rate_limit == 5
    assert not any("RATE_LIMIT" in c for c in changes)


def test_format_scope_summary_shows_path_exclusions_and_missing_header() -> None:
    settings = _settings()
    scope = CollectionScope.from_seeds(
        ["bancoplata.mx"],
        patterns=["*.bancoplata.mx", "!bancoplata.mx/*/whistleblowing"],
    )
    summary = format_scope_summary(scope, settings)
    assert "*.bancoplata.mx" in summary
    assert "! bancoplata.mx/*/whistleblowing" in summary
    assert "NOT configured" in summary


def test_format_scope_summary_shows_configured_attribution_header() -> None:
    settings = _settings(researcher_attribution_header={"X-HackerOne-Research": "my_h1_handle"})
    scope = CollectionScope.from_seeds(["bancoplata.mx"])
    summary = format_scope_summary(scope, settings)
    assert "configured" in summary
    assert "my_h1_handle" not in summary, "the handle itself should not be echoed verbatim"


def test_external_mode_gated_flags_match_active_direct_target_modules() -> None:
    assert set(EXTERNAL_MODE_GATED_FLAGS) == {
        "enable_param_fuzz",
        "enable_cloud_bucket_enum",
        "enable_browser_probe",
    }

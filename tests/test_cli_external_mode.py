"""`app.py:_external_mode_preflight` — the CLI-level wiring of
`core/external_mode.py` (pure logic, tested separately in
tests/test_external_mode.py). This drives the actual function including its
`input()`/non-interactive branch, without going through the full `main()`
CLI dispatch.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

import app as hydra_app
from config.settings import Settings


def _args(domain: str, *, external: bool = False) -> argparse.Namespace:
    return argparse.Namespace(domain=domain, targets_file=None, external=external)


def test_owned_domain_leaves_settings_untouched(tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path, owned_domains=("metaversejustice.com",))
    default_rate_limit = settings.rate_limit
    assert hydra_app._external_mode_preflight(_args("metaversejustice.com"), settings)
    assert settings.external_target_mode is False
    assert settings.rate_limit == default_rate_limit


def test_non_owned_domain_applies_conservative_defaults(tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path, owned_domains=("metaversejustice.com",))
    assert hydra_app._external_mode_preflight(_args("bancoplata.mx"), settings)
    assert settings.external_target_mode is True
    assert settings.rate_limit == Settings.EXTERNAL_MODE_RATE_LIMIT


def test_non_interactive_stdin_disables_gated_modules_without_prompting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Must never call input() when stdin isn't a real terminal — that would
    hang a CI run or an automated pipeline invocation."""
    settings = Settings(
        project_root=tmp_path,
        owned_domains=("metaversejustice.com",),
        enable_param_fuzz=True,
        enable_cloud_bucket_enum=True,
        enable_browser_probe=True,
    )

    def _fail_if_called(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("input() must not be called on non-interactive stdin")

    monkeypatch.setattr("builtins.input", _fail_if_called)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    assert hydra_app._external_mode_preflight(_args("bancoplata.mx"), settings)
    assert settings.enable_param_fuzz is False
    assert settings.enable_cloud_bucket_enum is False
    assert settings.enable_browser_probe is False


def test_interactive_decline_disables_only_gated_modules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(
        project_root=tmp_path,
        owned_domains=("metaversejustice.com",),
        enable_param_fuzz=True,
        enable_soft404_check=True,  # not gated — must survive a decline
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "n")

    assert hydra_app._external_mode_preflight(_args("bancoplata.mx"), settings)
    assert settings.enable_param_fuzz is False
    assert settings.enable_soft404_check is True


def test_interactive_confirm_leaves_gated_modules_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(
        project_root=tmp_path,
        owned_domains=("metaversejustice.com",),
        enable_param_fuzz=True,
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "y")

    assert hydra_app._external_mode_preflight(_args("bancoplata.mx"), settings)
    assert settings.enable_param_fuzz is True


def test_explicit_external_flag_forces_conservative_mode_even_for_owned_domain(
    tmp_path: Path,
) -> None:
    settings = Settings(project_root=tmp_path, owned_domains=("metaversejustice.com",))
    assert hydra_app._external_mode_preflight(
        _args("metaversejustice.com", external=True), settings
    )
    assert settings.external_target_mode is True
    assert settings.rate_limit == Settings.EXTERNAL_MODE_RATE_LIMIT

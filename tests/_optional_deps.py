"""Optional Python dependencies in tests: skip where they are legitimately
absent, fail loudly where they are supposed to be installed.

Tests for optional features (Playwright, Anthropic/OpenAI clients, python-
docx, ...) skip when the package is missing, so the lean Python-version CI
matrix can run without them. The risk is that a skip is silent: if the
fully provisioned environment (the Docker CI job, which installs
requirements-optional.txt) ever loses a package, its tests would quietly
stop running and CI would stay green.

`HYDRA_REQUIRE_OPTIONAL_DEPS=1` closes that gap. The Docker job sets it,
and then a missing optional package is an error, not a skip. Legitimate
environment skips (API keys, captured webhooks, external binaries) are
not affected; this only concerns Python packages.
"""

from __future__ import annotations

import functools
import importlib.util
import os
from typing import Any

import pytest

STRICT = os.environ.get("HYDRA_REQUIRE_OPTIONAL_DEPS") == "1"


def install_strict_importorskip() -> None:
    """In strict mode, make `pytest.importorskip` import for real, so a
    missing package fails the module instead of skipping it. Called once
    from conftest.py, before any test module is imported."""
    if not STRICT:
        return
    original = unpatched_importorskip()

    @functools.wraps(original)
    def import_or_fail(modname: str, *args: Any, **kwargs: Any) -> Any:
        # Only checks presence (find_spec loads no code); pytest's own
        # importorskip still does the actual import.
        _raise_if_missing(modname)
        return original(modname, *args, **kwargs)

    setattr(pytest, "importorskip", import_or_fail)  # noqa: B010 - patching pytest's own function


def unpatched_importorskip() -> Any:
    """pytest's own importorskip, even if strict mode already wrapped it
    (the wrapper keeps it as `__wrapped__`), so installing twice never
    stacks wrappers."""
    return getattr(pytest.importorskip, "__wrapped__", pytest.importorskip)


def requires_modules(*names: str) -> pytest.MarkDecorator:
    """A skip marker for tests that need `names` installed; in strict mode,
    a missing one raises at collection instead."""
    missing = _missing(names)
    if missing and STRICT:
        raise _strict_error(missing)
    return pytest.mark.skipif(bool(missing), reason=f"not installed: {', '.join(missing)}")


def _missing(names: tuple[str, ...]) -> list[str]:
    return [name for name in names if importlib.util.find_spec(name) is None]


def _raise_if_missing(name: str) -> None:
    if _missing((name,)):
        raise _strict_error([name])


def _strict_error(missing: list[str]) -> ModuleNotFoundError:
    return ModuleNotFoundError(
        f"HYDRA_REQUIRE_OPTIONAL_DEPS=1 but not installed: {', '.join(missing)}",
        name=missing[0],
    )

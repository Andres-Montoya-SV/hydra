"""HYDRA_REQUIRE_OPTIONAL_DEPS=1 turns "optional package missing" from a
skip into a failure (tests/_optional_deps.py), so the fully provisioned
Docker CI job can never silently stop running optional-feature tests."""

from __future__ import annotations

import importlib

import _optional_deps
import pytest

MISSING = "hydra_no_such_optional_package"


def _reload(monkeypatch: pytest.MonkeyPatch, *, strict: bool):  # noqa: ANN202
    # Start from pytest's own function even when this session already runs in
    # strict mode; monkeypatch restores it and the env var afterwards.
    monkeypatch.setattr(pytest, "importorskip", _optional_deps.unpatched_importorskip())
    if strict:
        monkeypatch.setenv("HYDRA_REQUIRE_OPTIONAL_DEPS", "1")
    else:
        monkeypatch.delenv("HYDRA_REQUIRE_OPTIONAL_DEPS", raising=False)
    module = importlib.reload(_optional_deps)
    module.install_strict_importorskip()
    return module


@pytest.fixture(autouse=True)
def _restore_module_state():  # noqa: ANN202
    yield
    importlib.reload(_optional_deps)


class TestDefaultMode:
    def test_a_missing_package_skips(self, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _reload(monkeypatch, strict=False)

        with pytest.raises(pytest.skip.Exception):
            pytest.importorskip(MISSING)
        assert module.requires_modules(MISSING).args[0] is True


class TestStrictMode:
    def test_importorskip_fails_instead_of_skipping(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _reload(monkeypatch, strict=True)

        with pytest.raises(ModuleNotFoundError):
            pytest.importorskip(MISSING)

    def test_requires_modules_fails_instead_of_skipping(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = _reload(monkeypatch, strict=True)

        with pytest.raises(ImportError, match=MISSING):
            module.requires_modules(MISSING)

    def test_installing_twice_never_stacks_wrappers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        module = _reload(monkeypatch, strict=True)
        module.install_strict_importorskip()

        assert pytest.importorskip.__wrapped__ is module.unpatched_importorskip()
        assert not hasattr(pytest.importorskip.__wrapped__, "__wrapped__")

    def test_installed_packages_behave_exactly_as_before(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = _reload(monkeypatch, strict=True)

        assert pytest.importorskip("json").__name__ == "json"
        assert module.requires_modules("json").args[0] is False

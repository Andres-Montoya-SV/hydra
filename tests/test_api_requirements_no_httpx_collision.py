"""Confirms `requirements-api.txt` itself never pulls in the Python
`httpx` package, directly or transitively — the actual, correct version
of the check requested when this project's httpx-shadowing incident was
audited (docs/PAID_API_DESIGN.md's "Round 1 implemented" section).

The original hypothesis was that installing `httpx[cli]` was the cause,
and that `requirements-api.txt` was where it came from. Neither part
held up: `httpx`'s `console_scripts` entry point is unconditional package
metadata (confirmed directly via `importlib.metadata` — not gated behind
the `cli` extra at all), and `httpx` isn't a dependency of
`requirements-api.txt` in the first place — it's a direct,
`requirements-dev.txt`-only pin, needed solely for
`fastapi.testclient.TestClient` in tests. `fastapi` itself DOES depend on
`httpx`, but only under its own `standard`/`standard-no-fastapi-cloud-cli`/
`all` extras — none of which `requirements-api.txt` requests (it pins
plain `fastapi==0.141.1`). This test locks that in, so a future edit that
casually adds `fastapi[standard]` (a very natural-looking "upgrade") to
`requirements-api.txt` doesn't silently reintroduce the same collision
for anyone who only ever installs the API's own requirements file,
without requirements-dev.txt's test dependencies.
"""

from __future__ import annotations

import importlib.metadata as metadata
import re
from pathlib import Path

import pytest


def _pinned_package_names(requirements_path: Path) -> list[str]:
    names = []
    for line in requirements_path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-r "):
            continue
        match = re.match(r"^([A-Za-z0-9_.\-]+)", line)
        if match:
            names.append(match.group(1))
    return names


class TestRequirementsApiNeverPullsInHttpx:
    def test_no_package_in_requirements_api_is_named_httpx(self) -> None:
        names = _pinned_package_names(Path("requirements-api.txt"))
        assert "httpx" not in {n.lower() for n in names}

    def test_none_of_requirements_apis_own_dependencies_require_httpx_unconditionally(
        self,
    ) -> None:
        names = _pinned_package_names(Path("requirements-api.txt"))
        for name in names:
            base_name = re.sub(r"\[.*\]", "", name)
            try:
                dist = metadata.distribution(base_name)
            except metadata.PackageNotFoundError:
                pytest.skip(f"{base_name} is not installed in this environment")
                continue
            for requirement in dist.requires or ():
                if not requirement.lower().startswith("httpx"):
                    continue
                # A conditional reference (e.g. `httpx<1,>=0.23; extra ==
                # "standard"`) is fine — it only activates for an extra
                # requirements-api.txt does not request. Only an
                # unconditional `httpx...` requirement (no `; extra ==`
                # marker at all) would mean installing `name` alone drags
                # httpx in.
                assert "extra ==" in requirement, (
                    f"{base_name} unconditionally requires {requirement!r} — "
                    "installing requirements-api.txt alone would pull in the "
                    "Python httpx package and its console-script collision "
                    "with the ProjectDiscovery httpx recon binary"
                )

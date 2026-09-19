"""Tracks `requirements-api.txt`'s relationship with the Python `httpx`
package across the two rounds that changed it — the actual, correct
concern from this project's original httpx-shadowing incident
(docs/PAID_API_DESIGN.md's "Round 1 implemented" section), updated for
Round 2's deliberate reversal.

**Round 1**: `httpx` (the Python package) was NOT a `requirements-api.txt`
dependency at all — it was a `requirements-dev.txt`-only pin, needed
solely for `fastapi.testclient.TestClient` in tests. This file originally
locked in "requirements-api.txt never pulls in httpx," so a future,
natural-looking edit (e.g. adding `fastapi[standard]`) wouldn't silently
reintroduce the same console-script collision with the ProjectDiscovery
`httpx` recon binary for anyone who only installs the API's own
requirements file.

**Round 2 deliberately reverses that**: `api/domain_verification.py`'s
well-known-file check needs a real `httpx.AsyncClient` to perform a real
HTTPS GET — the Python `httpx` package is now a genuine, intentional
`requirements-api.txt` runtime dependency (see the comment next to its
pin in that file). The underlying collision risk this file used to guard
against does not go away — it is mitigated the same way Round 1's own
"Known limitations" already documented for the ProjectDiscovery binary
itself: `core/dependencies/` verifies tool identity (`identity_markers`,
`path_denylist`) before ever trusting a discovered `httpx` on `PATH`
(exercised in `tests/test_dependency_binary_identity.py`), and this
service's own runtime code (`api/domain_verification.py`) imports the
Python package directly (`import httpx`) rather than shelling out to a
binary named `httpx` at all, so it is never subject to the PATH
collision in the first place — only ad-hoc command-line use of the
`httpx` console script is affected, exactly as Round 1's docs already
called out.
"""

from __future__ import annotations

import re
from pathlib import Path


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


class TestRequirementsApiIntentionallyPullsInHttpx:
    def test_httpx_is_pinned_as_a_genuine_runtime_dependency(self) -> None:
        """Confirms the Round 2 reversal is deliberate and pinned, not an
        accidental transitive pickup — if this ever starts failing
        because `httpx` was removed from `requirements-api.txt`, that's a
        sign the well-known-file verification method
        (`api/domain_verification.py::verify_well_known_file`) lost its
        runtime dependency, not that this test is stale."""
        names = {n.lower() for n in _pinned_package_names(Path("requirements-api.txt"))}
        assert "httpx" in names

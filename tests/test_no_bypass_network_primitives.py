"""Static architectural guard: security by construction, not by convention.

Every prior turn in this hardening arc closed a real gap where a built-in
collector opened its own socket/HTTP client instead of going through
`core/http_probe.py:http_get()` (proxy-aware) or the subprocess +
`_crawler_confinement` pattern (`modules/_base.py`). Those were each found by
manual/forensic audit. This test makes the *next* one impossible to merge
silently: it statically scans every `modules/*.py` file for a direct import
or call of a raw network primitive (`requests`, `aiohttp`, `urllib.request`,
`socket.socket`/`socket.create_connection`, `asyncio.open_connection`/
`asyncio.start_server`/`asyncio.open_unix_connection`) and fails unless that
module is explicitly allowlisted below with a stated reason.

This is deliberately a narrow, auditable check — an import/call-site scanner,
not a full data-flow analysis of whether a given URL is target-derived. It
cannot prove a new collector's destination is safe; it can only guarantee
that a new collector doing its own raw networking gets a human's attention
(an allowlist entry with a reason) before it ships silently. That is the gap
this file closes: today, nothing stops a contributor from adding
`requests.get(target_url)` to a new module and having it pass every other
test in the suite.
"""

from __future__ import annotations

import ast
from pathlib import Path

MODULES_DIR = Path(__file__).resolve().parent.parent / "modules"

# module filename -> why a raw network primitive there is safe. Every entry
# here connects to a FIXED, hardcoded third-party endpoint (never a
# target-derived hostname) — verified by reading each one; see
# docs/FINAL_NETWORK_CONFINEMENT_AUDIT.md's THIRD_PARTY_OBSERVATION rows.
# Adding a module here without that property (a fixed destination) defeats
# the entire point of this test.
ALLOWED_DIRECT_NETWORK_IMPORTS: dict[str, str] = {
    "ctlogs.py": (
        "fixed crt.sh endpoint (urllib.request); the seed domain is a query "
        "parameter, never the connection destination"
    ),
    "threat_intel.py": (
        "fixed URLhaus endpoint (urllib.request); target hostname is POST "
        "body content, never the connection destination"
    ),
    "vuln_match.py": (
        "fixed OSV.dev/WPScan endpoints (urllib.request); target-derived "
        "data is POST body/URL path segment, never the connection destination"
    ),
    "asn_lookup.py": (
        "fixed whois.cymru.com:43 (asyncio.open_connection) and Cymru's DNS "
        "zone (raw UDP socket); target IPs are WHOIS/DNS query content, "
        "never the connection destination"
    ),
}

# Infrastructure modules this guard doesn't apply to at all — they ARE the
# approved network layer other collectors are supposed to route through.
_EXEMPT_FILES = {"__init__.py", "_base.py"}

_PROHIBITED_TOP_LEVEL_IMPORTS = {"requests", "aiohttp"}
_PROHIBITED_DOTTED_IMPORTS = {"urllib.request"}
_PROHIBITED_CALLS = {
    ("socket", "socket"),
    ("socket", "create_connection"),
    ("asyncio", "open_connection"),
    ("asyncio", "start_server"),
    ("asyncio", "open_unix_connection"),
}


def _scan(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in _PROHIBITED_TOP_LEVEL_IMPORTS:
                    hits.append(f"import {alias.name}")
                if alias.name in _PROHIBITED_DOTTED_IMPORTS:
                    hits.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.split(".")[0] in _PROHIBITED_TOP_LEVEL_IMPORTS:
                hits.append(f"from {module} import ...")
            if module in _PROHIBITED_DOTTED_IMPORTS:
                hits.append(f"from {module} import ...")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func
            if isinstance(attr.value, ast.Name) and (attr.value.id, attr.attr) in _PROHIBITED_CALLS:
                hits.append(f"{attr.value.id}.{attr.attr}(...)")
    return hits


def test_builtin_collectors_do_not_use_raw_network_primitives_directly() -> None:
    violations: list[str] = []
    for path in sorted(MODULES_DIR.glob("*.py")):
        if path.name in _EXEMPT_FILES:
            continue
        hits = _scan(path)
        if not hits:
            continue
        if path.name in ALLOWED_DIRECT_NETWORK_IMPORTS:
            continue
        violations.append(f"{path.name}: {sorted(set(hits))}")
    assert not violations, (
        "New/undocumented direct network primitive use in a built-in collector "
        "module (modules/*.py):\n  " + "\n  ".join(violations) + "\n\n"
        "Target-directed network I/O must go through core/http_probe.py's "
        "http_get() (proxy-aware, core/collection/crawler_proxy.py) or the "
        "subprocess + self._crawler_confinement(context) pattern "
        "(modules/_base.py) — never open a socket/HTTP client directly. If "
        "this specific import genuinely connects only to a fixed, hardcoded "
        "third-party endpoint (never a target-derived hostname), add it to "
        "ALLOWED_DIRECT_NETWORK_IMPORTS in this test with that justification."
    )


def test_allowlist_entries_still_correspond_to_real_modules() -> None:
    """Catches allowlist drift: an entry naming a module that was renamed or
    deleted, silently loosening the guard for nothing."""
    for name in ALLOWED_DIRECT_NETWORK_IMPORTS:
        assert (MODULES_DIR / name).exists(), f"allowlisted module {name} no longer exists"


def test_guard_actually_fires_on_a_synthetic_bypass(tmp_path: Path) -> None:
    """Proves the scanner isn't a no-op: a synthetic file matching the exact
    pattern this guard exists to catch (`requests.get(target_url)` in a new,
    unlisted collector) must be flagged."""
    bad_file = tmp_path / "bad_collector.py"
    bad_file.write_text(
        "import requests\n\n" "def bad_collector(url):\n" "    return requests.get(url)\n"
    )
    hits = _scan(bad_file)
    assert hits, "the guard failed to detect a direct `requests` import"
    assert "bad_collector.py" not in ALLOWED_DIRECT_NETWORK_IMPORTS


def test_guard_detects_raw_socket_and_asyncio_connection_calls(tmp_path: Path) -> None:
    """Import-only scanning would miss `import asyncio` (used everywhere
    legitimately) followed by a raw `asyncio.open_connection(...)` call —
    this proves the call-site (not just import-site) detection works."""
    bad_file = tmp_path / "bad_raw_socket_collector.py"
    bad_file.write_text(
        "import asyncio\n\n"
        "async def bad_collector(host, port):\n"
        "    return await asyncio.open_connection(host, port)\n"
    )
    hits = _scan(bad_file)
    assert any("open_connection" in hit for hit in hits)

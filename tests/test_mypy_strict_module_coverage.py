"""Hardening round 2, Task 3: incremental mypy coverage for security-
sensitive modules must not silently regress back under the project-wide
`ignore_errors = true` blanket.

`pyproject.toml` carves out a second `[[tool.mypy.overrides]]` block
(mypy applies the *last* matching override for a module) that re-enables
real type checking for authorization, scope, network confinement, cache/
store, verification, and settings — each fixed to pass real checking
before being added (docs/HARDENING_ROUND2_P1.md documents every fix).
This test doesn't run mypy itself (that's the quality-gate step, not a
unit test) — it guards the *configuration*, so a future edit that removes
a module from this list (or deletes the override block entirely) fails
loudly here instead of silently widening the blanket ignore again.
"""

from __future__ import annotations

import re
from pathlib import Path

_PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"

# The exact set fixed and enabled this round — see
# docs/HARDENING_ROUND2_P1.md Task 3 for the reasoning behind each.
_EXPECTED_STRICT_MODULES = frozenset(
    {
        "core.intel.authorize",
        "core.scope",
        "core.intel.scope",
        "core.collection.audit",
        "core.collection.crawler_proxy",
        "core.collection.gateway",
        "core.collection.ssrf",
        "core.collection.target",
        "core.collection.whois_client",
        "core.store",
        "core.verification.detectors",
        "core.verification.grounding",
        "core.verification.model",
        "core.verification.postmodule",
        "core.verification.preflight",
        "config.settings",
    }
)


def _mypy_overrides() -> list[dict[str, object]]:
    """Minimal, targeted parse of this file's own `[[tool.mypy.overrides]]`
    blocks — no TOML library dependency (this project depends on none,
    and the stdlib `tomllib` isn't available on the Python 3.10 this
    project's own CI matrix still tests). Deliberately narrow: parses
    exactly the `module = [...]` / `ignore_errors = true|false` shape
    pyproject.toml's mypy section actually uses, not general TOML.
    """
    text = _PYPROJECT.read_text(encoding="utf-8")
    blocks = text.split("[[tool.mypy.overrides]]")[1:]
    overrides: list[dict[str, object]] = []
    for block in blocks:
        # Stop at the next top-level/double-bracket section, if any.
        next_section = re.search(r"\n\[", block)
        body = block[: next_section.start()] if next_section else block
        module_match = re.search(r"module\s*=\s*\[(.*?)\]", body, re.DOTALL)
        modules = (
            [m.strip().strip("\"'") for m in module_match.group(1).split(",") if m.strip()]
            if module_match
            else []
        )
        ignore_match = re.search(r"ignore_errors\s*=\s*(true|false)", body)
        ignore_errors = ignore_match.group(1) == "true" if ignore_match else None
        overrides.append({"module": modules, "ignore_errors": ignore_errors})
    return overrides


def test_strict_override_block_exists_with_ignore_errors_false() -> None:
    overrides = _mypy_overrides()
    strict_blocks = [o for o in overrides if o.get("ignore_errors") is False]
    assert len(strict_blocks) == 1, (
        "expected exactly one [[tool.mypy.overrides]] block with "
        "ignore_errors = false (the security-priority carve-out)"
    )


def test_every_expected_module_is_still_carved_out_of_the_blanket_ignore() -> None:
    overrides = _mypy_overrides()
    strict_modules: set[str] = set()
    for block in overrides:
        if block.get("ignore_errors") is False:
            strict_modules.update(block.get("module", []))
    missing = _EXPECTED_STRICT_MODULES - strict_modules
    assert missing == set(), (
        f"module(s) removed from mypy's strict carve-out without being "
        f"replaced: {sorted(missing)}. If a module was intentionally "
        "dropped, update _EXPECTED_STRICT_MODULES here and explain why."
    )


def test_blanket_ignore_block_still_exists_for_everything_else() -> None:
    """This isn't asking for less checking — it documents that the
    broad ignore is still the deliberate baseline for modules not yet
    audited, so this test fails loudly (not silently) if someone removes
    it outright expecting the whole repo to suddenly be strict-checked."""
    overrides = _mypy_overrides()
    blanket = [o for o in overrides if o.get("ignore_errors") is True]
    assert len(blanket) == 1
    assert "core.*" in blanket[0]["module"]

"""Hardening round 2, Task 2 (configuration consistency): every environment
variable `Settings.from_env()` actually reads must be documented in
`config/.env.example` (at minimum as a commented example) — and vice
versa, nothing should be documented there that the code never reads.

Real gap found and fixed this round: 23 variables (including `ENABLE_CACHE`,
explicitly named in this round's own task list) were read in
`config/settings.py` but never mentioned in `config/.env.example` at all —
an operator had no discoverable way to know these knobs existed short of
reading source. A separate real gap, `WHOIS_PATH`, was documented and
parsed but never actually consumed anywhere (`modules/whois.py` uses a
native client, not the system binary) — removed rather than documented,
since documenting a setting that does nothing would be actively misleading.

This test exists so the next new `os.getenv("SOME_NEW_VAR")` in
settings.py can't silently ship without a corresponding `.env.example`
entry — it is a durable guard, not a one-time manual sync.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent
_SETTINGS_PY = _REPO_ROOT / "config" / "settings.py"
_ENV_EXAMPLE = _REPO_ROOT / "config" / ".env.example"

# A handful of variables are intentionally read but not meant to appear as
# a plain "KEY=" line in .env.example — e.g. read via a different
# mechanism this regex-based check can't see, or legitimately internal.
# Empty today: every real gap found this round was fixed, not exempted.
_KNOWN_EXEMPT_FROM_ENV_EXAMPLE: frozenset[str] = frozenset()


def _env_vars_read_in_settings() -> set[str]:
    content = _SETTINGS_PY.read_text(encoding="utf-8")
    return set(re.findall(r'os\.getenv\("([A-Z_0-9]+)"', content))


def _env_vars_documented() -> set[str]:
    content = _ENV_EXAMPLE.read_text(encoding="utf-8")
    return set(re.findall(r"^#?\s*([A-Z_0-9]+)=", content, re.MULTILINE))


def test_every_env_var_read_by_settings_is_documented_in_env_example() -> None:
    read = _env_vars_read_in_settings()
    documented = _env_vars_documented()
    missing = sorted(read - documented - _KNOWN_EXEMPT_FROM_ENV_EXAMPLE)
    assert missing == [], (
        f"{len(missing)} env var(s) read in config/settings.py but absent from "
        f"config/.env.example (even as a commented example): {missing}. "
        "Add a line there — see docs/HARDENING_ROUND2_P1.md Task 2."
    )


def test_env_example_has_at_least_the_known_baseline_count() -> None:
    """A loose floor, not an exact-match ceiling: catches .env.example
    being accidentally truncated/emptied without being brittle about
    every single future addition."""
    documented = _env_vars_documented()
    assert len(documented) >= 100


def test_dead_whois_path_setting_was_removed_not_just_left_undocumented() -> None:
    """Regression guard for the specific dead-config finding this round:
    WHOIS_PATH must not silently come back as a Settings field/env read
    without modules/whois.py actually consuming it again."""
    from config.settings import Settings

    instance = Settings(project_root=_REPO_ROOT)
    assert not hasattr(instance, "whois_path")
    settings_content = _SETTINGS_PY.read_text(encoding="utf-8")
    assert "WHOIS_PATH" not in settings_content

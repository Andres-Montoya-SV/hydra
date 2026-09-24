"""Guards the exact drift this task exists to prevent: dev-tool versions
now live in two files that both name the same tools —
`requirements-dev.txt` (the real, CI-verified source of truth;
`.github/workflows/ci.yml`'s `check` job installs from it directly) and
`.pre-commit-config.yaml` (so a contributor's local `pre-commit run` uses
the identical toolchain CI does). Nothing stops a future PR from bumping
one and not the other by hand — this test is what stops it instead.

Deliberately parsed with plain string/regex scanning, not a YAML library
(`.pre-commit-config.yaml`'s structure is simple and stable, and this
avoids adding a real dependency — `import yaml` happens to work today only
because it's an undeclared transitive dependency of `bandit`, not
something this project actually pins). `pyproject.toml`'s own dev-tool
list was removed as part of this same task specifically because it was a
THIRD, unused copy of these pins (no `[build-system]` table exists, so
`pip install .[dev]` was never a real install path) — see that file's own
comment for the full reasoning; there is nothing left there to guard.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent

# Maps each pre-commit repo URL substring to the canonical tool name used
# in requirements-dev.txt, and the pre-commit hook's own version-tag
# convention: some tags carry a leading "v" (ruff, mypy's mirror repo),
# some don't (black, isort, bandit) — real, observed inconsistency across
# these specific upstream repos' own tagging schemes, not something to
# paper over by stripping "v" everywhere and hoping.
_REPO_TO_TOOL: tuple[tuple[str, str, bool], ...] = (
    ("github.com/psf/black", "black", False),
    ("github.com/PyCQA/isort", "isort", False),
    ("github.com/astral-sh/ruff-pre-commit", "ruff", True),
    ("github.com/pre-commit/mirrors-mypy", "mypy", True),
    ("github.com/PyCQA/bandit", "bandit", False),
)


def _parse_requirements_dev_pins(text: str) -> dict[str, str]:
    """`name==version` lines only — skips `-r other_file.txt` includes,
    comments, and continuation/option lines (there are none today, but a
    line-based parser should never silently misread one as a pin)."""
    pins: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.-]+)$", line)
        if match:
            pins[match.group(1).lower()] = match.group(2)
    return pins


def _parse_precommit_pins(text: str) -> dict[str, str]:
    """Walks `repo:`/`rev:` pairs in file order — `.pre-commit-config.yaml`
    always writes `rev:` as the line immediately following its own
    `repo:` line, which is enough structure to parse correctly here
    without a real YAML parser."""
    pins: dict[str, str] = {}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        repo_match = re.match(r"^\s*-\s*repo:\s*(\S+)", line)
        if not repo_match or i + 1 >= len(lines):
            continue
        repo_url = repo_match.group(1)
        rev_match = re.match(r"^\s*rev:\s*[\"']?([A-Za-z0-9_.-]+)[\"']?", lines[i + 1])
        if not rev_match:
            continue
        rev = rev_match.group(1)
        for substring, tool_name, has_v_prefix in _REPO_TO_TOOL:
            if substring in repo_url:
                pins[tool_name] = rev.lstrip("v") if has_v_prefix else rev
                break
    return pins


@pytest.fixture
def requirements_dev_pins() -> dict[str, str]:
    return _parse_requirements_dev_pins((_REPO_ROOT / "requirements-dev.txt").read_text())


@pytest.fixture
def precommit_pins() -> dict[str, str]:
    return _parse_precommit_pins((_REPO_ROOT / ".pre-commit-config.yaml").read_text())


class TestParsersActuallyFindTheRealPins:
    """Sanity checks on the parsers themselves — a parser that silently
    returns an empty dict would make every comparison test below
    vacuously pass, which is worse than not having the guard at all."""

    def test_requirements_dev_parser_finds_all_five_shared_tools(
        self, requirements_dev_pins: dict[str, str]
    ) -> None:
        for tool in ("black", "isort", "ruff", "mypy", "bandit"):
            assert tool in requirements_dev_pins, (
                f"{tool!r} not found in requirements-dev.txt by this parser — "
                "either the pin was removed or the parser regex needs updating"
            )

    def test_precommit_parser_finds_all_five_shared_tools(
        self, precommit_pins: dict[str, str]
    ) -> None:
        for tool in ("black", "isort", "ruff", "mypy", "bandit"):
            assert tool in precommit_pins, (
                f"{tool!r} not found in .pre-commit-config.yaml by this parser — "
                "either the hook was removed or the parser regex needs updating"
            )


class TestPinsAgree:
    def test_every_shared_tool_version_matches_between_the_two_files(
        self, requirements_dev_pins: dict[str, str], precommit_pins: dict[str, str]
    ) -> None:
        mismatches = {
            tool: (requirements_dev_pins[tool], precommit_pins[tool])
            for tool in requirements_dev_pins
            if tool in precommit_pins and requirements_dev_pins[tool] != precommit_pins[tool]
        }
        assert not mismatches, (
            "requirements-dev.txt and .pre-commit-config.yaml disagree on a tool "
            f"version — (requirements-dev.txt, pre-commit) per tool: {mismatches}. "
            "A contributor's local `pre-commit run` would use a different "
            "toolchain than CI actually runs."
        )

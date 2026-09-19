"""Shared test-support helper — deliberately NOT `conftest.py`: pytest
loads `conftest.py` through its own plugin mechanism, which does not
reliably support a plain `import conftest` from a sibling test module (no
`test_`/`Test` prefix, so pytest never tries to collect this file as
tests itself). `tests/conftest.py`'s `verified_httpx_path` fixture wraps
`verified_tool_path_or_skip` from here; `tests/test_dependency_binary_
identity.py` imports the same function directly to exercise the skip
decision itself, without needing a second pytest process.
"""

from __future__ import annotations

from pathlib import Path

import pytest


async def resolve_verified_tool_path(name: str) -> Path | None:
    """The real, identity-verified path for `name` — the same
    discovery+validation a real pipeline run uses
    (core/dependencies/service.py), never a bare PATH-searched guess.
    Returns None when nothing genuine can be found/verified — including
    when the only thing on PATH is a same-named impostor (Bug 1:
    `resolved_path` is only ever set on a HEALTHY report, never as a
    side effect of a rejected candidate)."""
    from core.dependencies.registry import get_tool_definition
    from core.dependencies.service import DependencyService

    service = DependencyService({name: Path(name)})
    report = await service.analyze_tool(get_tool_definition(name), Path(name), required=True)
    return report.resolved_path


async def verified_tool_path_or_skip(name: str) -> Path:
    path = await resolve_verified_tool_path(name)
    if path is None:
        pytest.skip(
            f"No genuine {name} binary found/verified in this environment "
            "(see docs/PAID_API_DESIGN.md's httpx-shadowing note) — a "
            "same-named impostor on PATH is treated identically to nothing "
            "being there at all, never run against by mistake"
        )
    return path

"""Missing CollectionScope must cause zero network I/O — for EVERY active-collection
plugin, not just dnsx/httpx/naabu.

Prior scope-authorization tests each hand-picked one or two plugins. This
parametrizes over every plugin the codebase itself declares
`active_collection = True` (`core.collectors.ACTIVE_COLLECTION_PLUGINS`) and
asserts on the actual network/subprocess primitives never being invoked —
not on an exception type, not on an empty output file — because a plugin
that swallows the missing-scope condition and returns cleanly without ever
touching the network is exactly as safe as one that raises loudly, and a
test that only checks "did it raise" would miss that distinction.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from config.settings import Settings
from core.collectors import ACTIVE_COLLECTION_PLUGINS, plugin_classes
from core.models import DomainTarget, PipelineContext
from core.plugin_base import ReconPlugin

_ACTIVE_PLUGIN_CLASSES = {
    cls.name: cls for cls in plugin_classes() if cls.name in ACTIVE_COLLECTION_PLUGINS
}


@pytest.mark.asyncio
@pytest.mark.parametrize("plugin_name", sorted(_ACTIVE_PLUGIN_CLASSES))
async def test_active_plugin_makes_zero_network_calls_without_scope(
    plugin_name: str, tmp_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def _record(name: str):
        def _fn(*args: object, **kwargs: object) -> None:
            calls.append(name)
            raise AssertionError(f"{name} must never be called without CollectionScope")

        return _fn

    async def _arecord(name: str):
        def _fn(*args: object, **kwargs: object):
            calls.append(name)
            raise AssertionError(f"{name} must never be called without CollectionScope")

        return _fn

    # Every network/subprocess primitive an active-collection plugin could
    # reach, patched at its defining module so every importer sees the patch.
    monkeypatch.setattr("utils.subprocess.run_command", _record("run_command"))
    monkeypatch.setattr("utils.subprocess.run_command_to_file", _record("run_command_to_file"))
    monkeypatch.setattr("core.http_probe.http_get", _record("http_get"))
    monkeypatch.setattr("utils.network.open_url", _record("open_url"))
    monkeypatch.setattr(
        "asyncio.open_connection", AsyncMock(side_effect=_record("asyncio.open_connection"))
    )

    output_dir = tmp_path / "run"
    output_dir.mkdir()
    context = PipelineContext(
        targets=[DomainTarget(domain="example.com")],
        output_dir=output_dir,
        collection_scope=None,  # the condition under test
        resolved=["example.com"],
        alive_urls=["https://example.com/"],
    )
    context.httpx_results = [
        {"input": "example.com", "url": "https://example.com/", "status_code": 200}
    ]

    input_path = output_dir / "input.txt"
    input_path.write_text("example.com\n", encoding="utf-8")

    plugin_cls = _ACTIVE_PLUGIN_CLASSES[plugin_name]
    plugin: ReconPlugin = plugin_cls(settings)

    try:
        await plugin.run(context, input_path)
    except AssertionError:
        raise
    except Exception as exc:
        # Any other exception (ConfigurationError, missing binary, bad
        # fixture shape, ...) is an acceptable way to fail closed here —
        # the only thing this test cares about is whether a network
        # primitive was reached first.
        print(f"{plugin_name}.run() raised (acceptable, fails closed): {exc!r}")

    assert calls == [], f"{plugin_name} invoked network/subprocess primitives without a scope"


def test_every_active_collection_plugin_is_covered_by_this_parametrization() -> None:
    """Guards against a future plugin quietly opting into active_collection
    without inheriting this coverage."""
    assert set(_ACTIVE_PLUGIN_CLASSES) == set(ACTIVE_COLLECTION_PLUGINS)
    assert len(_ACTIVE_PLUGIN_CLASSES) >= 15

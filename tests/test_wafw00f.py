"""`modules/wafw00f.py` — the WAF/CDN fingerprinting plugin.

`tests/fixtures/wafw00f_real_output.json` is the REAL, unmodified `wafw00f
-a -f json -o ... https://example.com` output captured during this task's
own development — not a guessed shape, and a real, confirmed example of
the exact contradiction risk this plugin's own parser guards against (a
real Cloudflare detection followed by a trailing generic-method
`detected: false` entry for the same URL).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from modules.wafw00f import Wafw00fPlugin, parse_wafw00f_results

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _real_fixture() -> list:
    with open(FIXTURES_DIR / "wafw00f_real_output.json", encoding="utf-8") as f:
        return json.load(f)


class TestParseWafw00fResultsAgainstTheRealFixture:
    def test_the_real_example_com_capture_detects_cloudflare(self) -> None:
        records = parse_wafw00f_results(_real_fixture())
        assert len(records) == 1
        assert records[0]["firewall"] == "Cloudflare"
        assert records[0]["manufacturer"] == "Cloudflare Inc."
        assert records[0]["url"] == "https://example.com"

    def test_the_trailing_generic_false_entry_is_never_kept(self) -> None:
        """The real fixture's second entry (`detected: false, firewall:
        "None"`) must never produce a record — proven against the real
        capture, not a synthetic stand-in."""
        records = parse_wafw00f_results(_real_fixture())
        assert all(r["firewall"] != "None" for r in records)


class TestParseWafw00fResultsEdgeCases:
    def test_no_detection_anywhere_produces_no_records(self) -> None:
        data = [
            {
                "detected": False,
                "firewall": "None",
                "manufacturer": "None",
                "url": "https://x.example",
            }
        ]
        assert parse_wafw00f_results(data) == []

    def test_non_list_input_is_handled_gracefully(self) -> None:
        assert parse_wafw00f_results({"unexpected": "shape"}) == []

    def test_multiple_real_detections_for_the_same_url_are_all_kept(self) -> None:
        data = [
            {
                "detected": True,
                "firewall": "Cloudflare",
                "manufacturer": "Cloudflare Inc.",
                "url": "https://x.example",
            },
            {
                "detected": True,
                "firewall": "AWS WAF",
                "manufacturer": "Amazon",
                "url": "https://x.example",
            },
            {
                "detected": False,
                "firewall": "None",
                "manufacturer": "None",
                "url": "https://x.example",
            },
        ]
        records = parse_wafw00f_results(data)
        assert {r["firewall"] for r in records} == {"Cloudflare", "AWS WAF"}


class TestScopeEnforcement:
    """Proves this active plugin re-authorizes every URL before handing
    it to the real `wafw00f` subprocess — the same class of test every
    other active plugin already has."""

    def _context(self, tmp_path: Path) -> PipelineContext:
        output_dir = tmp_path / "run"
        output_dir.mkdir()
        (output_dir / "alive.txt").write_text(
            "https://example.com\nhttps://evil-out-of-scope.example\n", encoding="utf-8"
        )
        return PipelineContext(
            targets=[DomainTarget(domain="example.com")],
            output_dir=output_dir,
            collection_scope=CollectionScope.from_seeds(["example.com"]),
        )

    @pytest.mark.asyncio
    async def test_an_out_of_scope_url_never_reaches_the_real_tool_invocation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(project_root=tmp_path, enable_wafw00f=True)
        context = self._context(tmp_path)
        plugin = Wafw00fPlugin(settings)

        captured_args: list[str] = []

        async def fake_run_tool(self_, ctx, args, *, timeout=None):  # noqa: ANN001
            captured_args.extend(args)
            (tmp_path / "run" / "wafw00f.json").write_text("[]", encoding="utf-8")
            return 0, "", ""

        import modules.wafw00f as wafw00f_module

        monkeypatch.setattr(wafw00f_module.Wafw00fPlugin, "_run_tool", fake_run_tool)
        await plugin.run(context, tmp_path / "unused")

        joined = " ".join(captured_args)
        assert "example.com" in joined
        assert "evil-out-of-scope.example" not in joined

    @pytest.mark.asyncio
    async def test_noredirect_flag_is_always_passed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The one way wafw00f could otherwise leave the authorized
        target (a 3xx redirect) — `-r` must always be in the real argv,
        not an optional/forgettable flag."""
        settings = Settings(project_root=tmp_path, enable_wafw00f=True)
        context = self._context(tmp_path)
        plugin = Wafw00fPlugin(settings)

        captured_args: list[str] = []

        async def fake_run_tool(self_, ctx, args, *, timeout=None):  # noqa: ANN001
            captured_args.extend(args)
            (tmp_path / "run" / "wafw00f.json").write_text("[]", encoding="utf-8")
            return 0, "", ""

        import modules.wafw00f as wafw00f_module

        monkeypatch.setattr(wafw00f_module.Wafw00fPlugin, "_run_tool", fake_run_tool)
        await plugin.run(context, tmp_path / "unused")

        assert "-r" in captured_args

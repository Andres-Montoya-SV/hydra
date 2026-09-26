"""WhatWeb provider tests: normalization and authorization invariants."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from config.settings import Settings
from core.assets import Host, HttpService, TechnologyFinding
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.parsers.registry import parse_tool_output
from modules.whatweb import WhatWebPlugin, parse_whatweb_results


class TestParseWhatWebResults:
    def test_normalizes_products_and_versions_but_drops_metadata_plugins(self) -> None:
        data = [
            {
                "target": "https://app.example.com",
                "http_status": 200,
                "plugins": {
                    "Apache": {"version": ["2.4.62"]},
                    "WordPress": {},
                    "HTTPServer": {"string": ["Apache/2.4.62"]},
                    "Title": {"string": ["Example"]},
                    "IP": {"string": ["203.0.113.10"]},
                },
            }
        ]
        records = parse_whatweb_results(data)
        assert {r["technology"] for r in records} == {"Apache", "WordPress", "HTTPServer"}
        apache = next(r for r in records if r["technology"] == "Apache")
        assert apache["version"] == "2.4.62"
        assert apache["host"] == "app.example.com"
        assert apache["source"] == "whatweb"

    def test_duplicate_plugin_records_are_collapsed(self) -> None:
        row = {
            "target": "https://example.com",
            "plugins": {"nginx": {"version": ["1.26"]}},
        }
        assert len(parse_whatweb_results([row, row])) == 1

    def test_malformed_shape_is_safe(self) -> None:
        assert parse_whatweb_results({"plugins": {}}) == []
        assert parse_whatweb_results([{}, {"target": "https://example.com", "plugins": []}]) == []


class TestWhatWebParserIntegration:
    def test_normalized_artifact_enters_existing_technology_finding_model(
        self, tmp_path: Path
    ) -> None:
        artifact = tmp_path / "whatweb_technologies.jsonl"
        artifact.write_text(
            json.dumps(
                {
                    "host": "app.example.com",
                    "url": "https://app.example.com",
                    "technology": "WordPress",
                    "version": "6.8",
                    "source": "whatweb",
                    "confidence_score": 80,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        hosts, warnings = parse_tool_output("whatweb", tmp_path, artifact=artifact)
        assert warnings == []
        assert len(hosts) == 1
        service = hosts[0].http_services[0]
        assert service.technologies[0].name == "WordPress"
        assert service.technologies[0].version == "6.8"
        assert service.technologies[0].source == "whatweb"


class TestTechnologyProviderMerge:
    def test_whatweb_enrichment_survives_existing_httpx_service(self) -> None:
        canonical = Host(
            domain="example.com",
            http_services=[
                HttpService(
                    url="https://example.com/",
                    host="example.com",
                    source="httpx",
                    technologies=[
                        TechnologyFinding(name="nginx", source="httpx", confidence=80)
                    ],
                )
            ],
        )
        enrichment = Host(
            domain="example.com",
            http_services=[
                HttpService(
                    url="https://example.com/",
                    host="example.com",
                    source="whatweb",
                    technologies=[
                        TechnologyFinding(
                            name="WordPress",
                            version="6.8",
                            source="whatweb",
                            confidence=80,
                        )
                    ],
                )
            ],
        )

        canonical.merge_from(enrichment)

        assert len(canonical.http_services) == 1
        technologies = canonical.http_services[0].technologies
        assert {(item.name, item.version, item.source) for item in technologies} == {
            ("nginx", None, "httpx"),
            ("WordPress", "6.8", "whatweb"),
        }


class TestWhatWebAuthorization:
    def _context(self, tmp_path: Path) -> PipelineContext:
        output_dir = tmp_path / "run"
        output_dir.mkdir()
        (output_dir / "alive.txt").write_text(
            "https://example.com\nhttps://evil-out-of-scope.example\n",
            encoding="utf-8",
        )
        return PipelineContext(
            targets=[DomainTarget(domain="example.com")],
            output_dir=output_dir,
            collection_scope=CollectionScope.from_seeds(["example.com"]),
        )

    @pytest.mark.asyncio
    async def test_out_of_scope_url_never_reaches_whatweb_argv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(project_root=tmp_path, enable_whatweb=True)
        context = self._context(tmp_path)
        plugin = WhatWebPlugin(settings)
        captured: list[str] = []

        async def fake_run_tool(self_, ctx, args, *, input_data=None, timeout=None):  # noqa: ANN001
            captured.extend(args)
            (tmp_path / "run" / "whatweb.json").write_text(
                json.dumps([{"target": "https://example.com", "plugins": {"nginx": {}}}]),
                encoding="utf-8",
            )
            return 0, "", ""

        class FakeProxy:
            proxy_url = "http://127.0.0.1:7777"

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def fake_confinement(self_, ctx):  # noqa: ANN001
            yield FakeProxy()

        monkeypatch.setattr(WhatWebPlugin, "_run_tool", fake_run_tool)
        monkeypatch.setattr(WhatWebPlugin, "_crawler_confinement", fake_confinement)

        result = await plugin.run(context, tmp_path / "unused")
        assert result.success is True
        joined = " ".join(captured)
        assert "https://example.com" in joined
        assert "evil-out-of-scope.example" not in joined
        assert "--follow-redirect=never" in captured
        assert "--proxy" in captured

    @pytest.mark.asyncio
    async def test_program_attribution_is_forwarded_to_whatweb(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings(
            project_root=tmp_path,
            enable_whatweb=True,
            user_agent="hydra/1.0",
            attribution_user_agent="bugcrowd; researcher",
            researcher_attribution_header={"X-HackerOne-Research": "researcher"},
        )
        context = self._context(tmp_path)
        plugin = WhatWebPlugin(settings)
        captured: list[str] = []

        async def fake_run_tool(self_, ctx, args, *, input_data=None, timeout=None):  # noqa: ANN001
            captured.extend(args)
            (tmp_path / "run" / "whatweb.json").write_text("[]", encoding="utf-8")
            return 0, "", ""

        class FakeProxy:
            proxy_url = "http://127.0.0.1:7777"

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def fake_confinement(self_, ctx):  # noqa: ANN001
            yield FakeProxy()

        monkeypatch.setattr(WhatWebPlugin, "_run_tool", fake_run_tool)
        monkeypatch.setattr(WhatWebPlugin, "_crawler_confinement", fake_confinement)

        await plugin.run(context, tmp_path / "unused")
        joined = " ".join(captured)
        assert "--aggression=1" in captured
        assert "--user-agent" in captured
        assert "bugcrowd; researcher" in joined
        assert "--header" in captured
        assert "X-HackerOne-Research:researcher" in joined

    def test_disabled_by_default(self, tmp_path: Path) -> None:
        assert WhatWebPlugin(Settings(project_root=tmp_path)).is_enabled() is False

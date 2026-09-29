"""A collector whose upstream service can't be reached must record
UNAVAILABLE (or PARTIAL), never a clean `success_no_results`.

Before this, CT logs and ASN lookup caught every upstream error and
returned success with zero results, which the runner recorded as a clean
empty run. For CT logs that also defeated monitoring's degraded-run check:
a crt.sh outage looked like "no certificates", so hosts only CT logs knows
about were reported as removed."""

from __future__ import annotations

from pathlib import Path

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext, ToolStatus
from core.provider_contract import execution_status_for_result
from modules.asn_lookup import AsnLookupPlugin
from modules.ctlogs import CtlogsPlugin
from utils.files import write_jsonl


def _context(tmp_path: Path, domains: list[str]) -> PipelineContext:
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    return PipelineContext(output_dir=output_dir, targets=[DomainTarget(domain=d) for d in domains])


def _ctlogs(tmp_path: Path) -> CtlogsPlugin:
    settings = Settings(project_root=tmp_path)
    settings.ctlogs_delay_seconds = 0
    return CtlogsPlugin(settings)


def _crtsh_failing_for(failing: set[str]):  # noqa: ANN202
    def fetch(domain, *args):  # noqa: ANN001, ANN202
        if domain in failing:
            raise TimeoutError("crt.sh timed out")
        return [{"id": 1, "name_value": f"www.{domain}"}]

    return fetch


class TestCertificateTransparency:
    async def test_every_query_failing_is_unavailable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("modules.ctlogs._fetch_crtsh", _crtsh_failing_for({"a.test"}))
        context = _context(tmp_path, ["a.test"])

        result = await _ctlogs(tmp_path).run(context, context.output_dir / "targets.txt")

        assert result.success  # the scan still continues
        assert execution_status_for_result(result) is ToolStatus.UNAVAILABLE

    async def test_some_queries_failing_is_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("modules.ctlogs._fetch_crtsh", _crtsh_failing_for({"b.test"}))
        context = _context(tmp_path, ["a.test", "b.test"])

        result = await _ctlogs(tmp_path).run(context, context.output_dir / "targets.txt")

        assert execution_status_for_result(result) is ToolStatus.PARTIAL

    async def test_all_queries_succeeding_is_a_clean_result(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("modules.ctlogs._fetch_crtsh", _crtsh_failing_for(set()))
        context = _context(tmp_path, ["a.test"])

        result = await _ctlogs(tmp_path).run(context, context.output_dir / "targets.txt")

        assert execution_status_for_result(result) is ToolStatus.SUCCESS_WITH_RESULTS


class TestAsnLookup:
    async def test_unreachable_team_cymru_is_unavailable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        context = _context(tmp_path, ["a.test"])
        # asn_lookup fails closed without an explicit scope, as it should.
        context.collection_scope = CollectionScope.from_seeds(["a.test"])
        write_jsonl(
            context.output_dir / "dnsx_records.jsonl", [{"host": "a.test", "a": ["192.0.2.10"]}]
        )

        async def unreachable(_ips: list[str]) -> list[dict[str, str]]:
            raise TimeoutError()

        monkeypatch.setattr("modules.asn_lookup._query_cymru", unreachable)
        settings = Settings(project_root=tmp_path)
        settings.asn_lookup_timeout = 5

        result = await AsnLookupPlugin(settings).run(context, context.output_dir / "resolved.txt")

        assert result.success  # soft-fail: the scan continues
        assert execution_status_for_result(result) is ToolStatus.UNAVAILABLE

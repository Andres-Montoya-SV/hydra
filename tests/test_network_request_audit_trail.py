"""`intel_network_requests`: proves the CLI/an analyst can answer, from SQLite
alone, "was this host actually contacted, under which authorization, why" —
for both the crawler-confinement proxy and httpx's redirect-hop resolver,
the two components that make individual per-destination decisions outside
the input-file gate.
"""

from __future__ import annotations

import pytest

from config.settings import Settings
from core.assets import ScanRun
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.store import AssetStore
from modules.httpx import HttpxPlugin
from modules.katana import KatanaPlugin

SEED = "app.audit-trail-test.internal"
OOS = "evil.audit-trail-test.internal"


def _scope() -> CollectionScope:
    return CollectionScope.from_seeds([SEED], patterns=[SEED])


@pytest.mark.asyncio
async def test_crawler_proxy_decisions_land_in_sqlite(tmp_path) -> None:
    settings = Settings(project_root=tmp_path)
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        output_dir=output_dir,
        collection_scope=_scope(),
        run_id="audit-crawler",
    )
    plugin = KatanaPlugin(settings)

    async with plugin._crawler_confinement(context) as proxy:
        # Drive real decisions through the real proxy (no raw sockets needed
        # here — the crawler_proxy/crawler_confinement_live test files
        # already prove the wire protocol; this test proves the audit sink).
        proxy._record(method="CONNECT", host=SEED, port=443, allowed=True, reason="in_scope")
        proxy.audit[-1].network_completed = True
        proxy._record(method="CONNECT", host=OOS, port=443, allowed=False, reason="out_of_scope")

    assert isinstance(context.metadata.get("network_requests"), list)
    assert len(context.metadata["network_requests"]) == 2

    store = AssetStore(tmp_path / "recon.db")
    store.create_run(
        ScanRun(run_id="audit-crawler", started_at="2026-01-01T00:00:00Z", targets=[SEED])
    )
    store.record_network_requests("audit-crawler", context.metadata["network_requests"])

    allowed_rows = store.get_network_requests("audit-crawler", decision="ALLOW")
    denied_rows = store.get_network_requests("audit-crawler", decision="DENY")

    assert len(allowed_rows) == 1
    assert allowed_rows[0]["normalized_hostname"] == SEED
    assert allowed_rows[0]["network_attempted"] == 1
    assert allowed_rows[0]["network_completed"] == 1
    assert allowed_rows[0]["collector"] == "katana"

    assert len(denied_rows) == 1
    assert denied_rows[0]["normalized_hostname"] == OOS
    assert denied_rows[0]["network_attempted"] == 0
    assert denied_rows[0]["reason"] == "out_of_scope"

    # The invariant the mission asks the audit trail to prove mechanically:
    # nothing that wasn't ALLOWed shows network_attempted.
    all_rows = store.get_network_requests("audit-crawler")
    assert all(r["network_attempted"] == 0 for r in all_rows if r["decision"] != "ALLOW")


@pytest.mark.asyncio
async def test_httpx_redirect_hop_decisions_land_in_sqlite(tmp_path) -> None:
    settings = Settings(project_root=tmp_path)
    plugin = HttpxPlugin(settings)
    scope = _scope()

    async def fake_fetch(context, target, *, suffix, record_index, hop):
        return None  # denies never reach this; allow-path doesn't need real data here

    plugin._fetch_single_hop = fake_fetch  # type: ignore[method-assign]

    output_dir = tmp_path / "run"
    output_dir.mkdir()
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        output_dir=output_dir,
        collection_scope=scope,
        run_id="audit-httpx",
    )

    record = {
        "input": SEED,
        "host": SEED,
        "url": f"https://{SEED}/",
        "status_code": 302,
        "location": f"https://{OOS}/x",
    }
    await plugin._resolve_authorized_redirects(context, record, scope, "", 0)

    requests = context.metadata.get("network_requests")
    assert isinstance(requests, list) and len(requests) == 1
    assert requests[0]["decision"] == "DENY"
    assert requests[0]["normalized_hostname"] == OOS
    assert requests[0]["network_attempted"] is False

    store = AssetStore(tmp_path / "recon.db")
    store.create_run(
        ScanRun(run_id="audit-httpx", started_at="2026-01-01T00:00:00Z", targets=[SEED])
    )
    store.record_network_requests("audit-httpx", requests)

    rows = store.get_network_requests("audit-httpx")
    assert len(rows) == 1
    assert rows[0]["collector"] == "httpx"
    assert rows[0]["decision"] == "DENY"
    assert rows[0]["network_attempted"] == 0
    assert OOS in rows[0]["url"]

"""`modules/dnsx.py`: NODATA (NOERROR, SOA-only, no A/AAAA) must never count
as resolved.

Real case (fishbowlapp.com): 9 passively-discovered subdomains
(`jenkins.api.fishbowlapp.com` and 8 siblings) each got a dnsx record with
`"status_code": "NOERROR"` and only an `soa` field — no `a`/`aaaa` at all.
`resolved_hosts.append(host)` fired for every JSON line with a `host`
field, regardless of whether it actually had an address, so all 9 landed in
`resolved.txt` and were then handed to httpx as live targets. Independently
verified real (not a transient DNS change): `dig +short
jenkins.api.fishbowlapp.com` and `curl -v http://jenkins.api.fishbowlapp.com`
both confirmed no resolution, hours after the scan.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from core.plugin_base import PluginResult
from modules.dnsx import DnsxPlugin
from utils.files import read_lines, write_lines

# The exact 9 real records from the fishbowlapp.com run — SOA only, no
# a/aaaa, status_code NOERROR (NODATA, not a resolution failure the status
# code alone would reveal).
FISHBOWL_NODATA_HOSTS = [
    "jenkins.api.fishbowlapp.com",
    "monitor.api.fishbowlapp.com",
    "account.api.fishbowlapp.com",
    "portal.api.fishbowlapp.com",
    "login.api.fishbowlapp.com",
    "mail.api.fishbowlapp.com",
    "internal.api.fishbowlapp.com",
    "remote.api.fishbowlapp.com",
    "api.api.fishbowlapp.com",
]


def _fishbowl_nodata_record(host: str) -> dict:
    return {
        "host": host,
        "ttl": 1800,
        "resolver": ["1.1.1.1:53"],
        "soa": [
            {
                "name": "fishbowlapp.com",
                "ns": "irma.ns.cloudflare.com",
                "mailbox": "dns.cloudflare.com",
                "serial": 2413370437,
                "refresh": 10000,
                "retry": 2400,
                "expire": 604800,
                "minttl": 1800,
            }
        ],
        "status_code": "NOERROR",
        "timestamp": "2026-09-01T18:00:59.841869-06:00",
    }


def _context(tmp_path: Path, seed: str = "fishbowlapp.com") -> PipelineContext:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    return PipelineContext(
        targets=[DomainTarget(domain=seed)],
        output_dir=output_dir,
        collection_scope=CollectionScope.from_seeds([seed], patterns=[f"*.{seed}", seed]),
    )


def _mock_execute_self_output(records: list[dict]):
    async def fake(context, args, output_path, *, input_data=None, allow_empty=False):
        lines = "\n".join(json.dumps(r) for r in records) + ("\n" if records else "")
        output_path.write_text(lines, encoding="utf-8")
        return PluginResult(success=True, output_path=output_path, lines_produced=len(records))

    return fake


@pytest.mark.asyncio
async def test_dnsx_nodata_soa_only_is_not_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact real fishbowlapp.com case: 9 SOA-only NODATA records must
    not appear in resolved.txt / context.resolved."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    input_path = context.output_dir / "subdomains.txt"
    write_lines(input_path, FISHBOWL_NODATA_HOSTS, base_dir=context.output_dir)

    records = [_fishbowl_nodata_record(h) for h in FISHBOWL_NODATA_HOSTS]
    plugin = DnsxPlugin(settings)
    monkeypatch.setattr(plugin, "_execute_self_output", _mock_execute_self_output(records))

    await plugin.run(context, input_path)

    resolved = read_lines(context.output_dir / "resolved.txt")
    assert resolved == []
    assert context.resolved == []


@pytest.mark.asyncio
async def test_dnsx_real_a_record_still_counts_as_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No regression: a host with a real A record must still resolve."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path, seed="example.com")
    input_path = context.output_dir / "subdomains.txt"
    write_lines(input_path, ["www.example.com"], base_dir=context.output_dir)

    records = [{"host": "www.example.com", "a": ["93.184.216.34"], "status_code": "NOERROR"}]
    plugin = DnsxPlugin(settings)
    monkeypatch.setattr(plugin, "_execute_self_output", _mock_execute_self_output(records))

    await plugin.run(context, input_path)

    resolved = read_lines(context.output_dir / "resolved.txt")
    assert resolved == ["www.example.com"]
    assert context.resolved == ["www.example.com"]


@pytest.mark.asyncio
async def test_dnsx_aaaa_only_record_also_counts_as_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path, seed="example.com")
    input_path = context.output_dir / "subdomains.txt"
    write_lines(input_path, ["v6.example.com"], base_dir=context.output_dir)

    records = [{"host": "v6.example.com", "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"]}]
    plugin = DnsxPlugin(settings)
    monkeypatch.setattr(plugin, "_execute_self_output", _mock_execute_self_output(records))

    await plugin.run(context, input_path)

    assert read_lines(context.output_dir / "resolved.txt") == ["v6.example.com"]


@pytest.mark.asyncio
async def test_dnsx_mixed_batch_only_addressed_hosts_survive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A realistic batch: some genuinely resolve, most (the fishbowlapp.com
    case) are NODATA — only the resolved ones must survive."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path)
    all_hosts = ["api.fishbowlapp.com", "www.fishbowlapp.com", *FISHBOWL_NODATA_HOSTS]
    input_path = context.output_dir / "subdomains.txt"
    write_lines(input_path, all_hosts, base_dir=context.output_dir)

    records = [
        {"host": "api.fishbowlapp.com", "a": ["104.18.32.42", "172.64.155.214"]},
        {"host": "www.fishbowlapp.com", "a": ["172.64.155.214", "104.18.32.42"]},
        *[_fishbowl_nodata_record(h) for h in FISHBOWL_NODATA_HOSTS],
    ]
    plugin = DnsxPlugin(settings)
    monkeypatch.setattr(plugin, "_execute_self_output", _mock_execute_self_output(records))

    await plugin.run(context, input_path)

    resolved = set(read_lines(context.output_dir / "resolved.txt"))
    assert resolved == {"api.fishbowlapp.com", "www.fishbowlapp.com"}
    for host in FISHBOWL_NODATA_HOSTS:
        assert host not in resolved


@pytest.mark.asyncio
async def test_dnsx_empty_a_list_is_not_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defensive: an explicit empty list is exactly as unresolved as a
    missing key — dnsx/downstream tooling should never emit this, but the
    check must not be fooled by a falsy-but-present field either."""
    settings = Settings(project_root=tmp_path)
    context = _context(tmp_path, seed="example.com")
    input_path = context.output_dir / "subdomains.txt"
    write_lines(input_path, ["empty.example.com"], base_dir=context.output_dir)

    records = [{"host": "empty.example.com", "a": [], "aaaa": [], "status_code": "NOERROR"}]
    plugin = DnsxPlugin(settings)
    monkeypatch.setattr(plugin, "_execute_self_output", _mock_execute_self_output(records))

    await plugin.run(context, input_path)

    assert read_lines(context.output_dir / "resolved.txt") == []

"""`modules/passive_dns.py`: candidate selection, provider resilience, and
the never-resolve-the-sibling-directly contract.

Candidates come only from this run's own `ctlogs.jsonl` (certificate SANs
already observed), filtered to the ones `allows_active_collection` denies —
never an arbitrary hostname. The provider calls themselves
(`_query_mnemonic`/`_query_securitytrails`) are mocked at the function
boundary, the same convention `tests/test_alive_txt_integrity_matrix.py`
already uses for `modules/threat_intel.py`'s `_query_urlhaus` — this proves
the plugin's own candidate-selection/error-handling logic, independent of
whether the real HTTP endpoints are reachable.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from config.settings import Settings
from core.intel.scope import CollectionScope
from core.models import DomainTarget, PipelineContext
from modules.passive_dns import PassiveDnsPlugin, _sibling_candidates
from utils.files import read_jsonl, write_jsonl

SEED = "virusbarrier.xyz"
SIBLINGS = [
    "virusinspector.top",
    "cybermedic.buzz",
    "defendervault.shop",
    "shieldvertex.mom",
    "safesentinel.lol",
]
IP = "34.75.127.116"


def _context(tmp_path: Path, *, max_candidates: int = 25) -> tuple[PipelineContext, Settings]:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    scope = CollectionScope.from_seeds([SEED], patterns=[SEED])
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)],
        output_dir=output_dir,
        collection_scope=scope,
        run_id="passive-dns-test",
    )
    write_jsonl(
        output_dir / "ctlogs.jsonl",
        [
            {
                "id": 1,
                "common_name": "virusinspector.top",
                "name_value": "\n".join([SEED, *SIBLINGS]),
                "query_domain": SEED,
            }
        ],
        base_dir=output_dir,
    )
    settings = Settings(
        project_root=tmp_path,
        enable_passive_dns=True,
        passive_dns_max_candidates=max_candidates,
        passive_dns_delay_seconds=0,
    )
    return context, settings


def test_is_disabled_by_default() -> None:
    settings = Settings(project_root=Path("."))
    assert settings.enable_passive_dns is False


def test_candidates_are_only_out_of_scope_certificate_siblings(tmp_path: Path) -> None:
    context, _settings = _context(tmp_path)
    candidates = _sibling_candidates(context, 25)
    assert set(candidates) == set(SIBLINGS)
    assert SEED not in candidates


def test_candidates_capped_by_max_candidates(tmp_path: Path) -> None:
    context, _settings = _context(tmp_path, max_candidates=2)
    candidates = _sibling_candidates(context, 2)
    assert len(candidates) == 2
    assert set(candidates) <= set(SIBLINGS)


def test_no_ctlogs_artifact_skips_cleanly(tmp_path: Path) -> None:
    output_dir = tmp_path / "run"
    output_dir.mkdir()
    scope = CollectionScope.from_seeds([SEED], patterns=[SEED])
    context = PipelineContext(
        targets=[DomainTarget(domain=SEED)], output_dir=output_dir, collection_scope=scope
    )
    assert _sibling_candidates(context, 25) == []


@pytest.mark.asyncio
async def test_run_writes_provider_shaped_jsonl_and_never_queries_seed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, settings = _context(tmp_path)
    plugin = PassiveDnsPlugin(settings)
    queried: list[str] = []

    def fake_mnemonic(host, timeout, user_agent, proxy_url):
        queried.append(host)
        return ({IP}, "111", "222", f"# {host} mnemonic\n{{}}")

    monkeypatch.setattr("modules.passive_dns._query_mnemonic", fake_mnemonic)

    result = await plugin.run(context, tmp_path / "unused")

    assert result.success
    assert SEED not in queried
    assert set(queried) == set(SIBLINGS)

    records = read_jsonl(context.output_dir / "passive_dns.jsonl")
    assert len(records) == len(SIBLINGS)
    for record in records:
        assert record["host"] in SIBLINGS
        assert record["ip"] == [IP]
        assert record["collector"] == "passive_dns"
        assert record["source"] == "passive_dns"
        assert record["query_status"] == "ok"
        assert record["raw_artifact"]


@pytest.mark.asyncio
async def test_empty_provider_response_adds_no_evidence_and_does_not_break(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, settings = _context(tmp_path)
    plugin = PassiveDnsPlugin(settings)

    def fake_mnemonic(host, timeout, user_agent, proxy_url):
        return (set(), None, None, f"# {host} mnemonic\n{{}}")

    monkeypatch.setattr("modules.passive_dns._query_mnemonic", fake_mnemonic)

    result = await plugin.run(context, tmp_path / "unused")

    assert result.success
    records = read_jsonl(context.output_dir / "passive_dns.jsonl")
    assert len(records) == len(SIBLINGS)
    for record in records:
        assert record["ip"] == []
        assert record["query_status"] == "empty"


@pytest.mark.asyncio
async def test_provider_timeout_fails_clean_and_skips_only_that_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, settings = _context(tmp_path)
    plugin = PassiveDnsPlugin(settings)

    def fake_mnemonic(host, timeout, user_agent, proxy_url):
        if host == SIBLINGS[0]:
            raise TimeoutError("simulated provider timeout")
        return ({IP}, None, None, f"# {host} mnemonic\n{{}}")

    monkeypatch.setattr("modules.passive_dns._query_mnemonic", fake_mnemonic)

    result = await plugin.run(context, tmp_path / "unused")

    assert result.success, "one host's timeout must not fail the whole run"
    records = {r["host"]: r for r in read_jsonl(context.output_dir / "passive_dns.jsonl")}
    assert records[SIBLINGS[0]]["query_status"] == "error"
    assert records[SIBLINGS[0]]["ip"] == []
    assert "error" in records[SIBLINGS[0]]
    for host in SIBLINGS[1:]:
        assert records[host]["query_status"] == "ok"
        assert records[host]["ip"] == [IP]
    assert any("Passive DNS" in w for w in context.warnings)


@pytest.mark.asyncio
async def test_securitytrails_not_queried_without_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, settings = _context(tmp_path)
    assert settings.securitytrails_api_key is None
    plugin = PassiveDnsPlugin(settings)

    def fake_mnemonic(host, timeout, user_agent, proxy_url):
        return (set(), None, None, "raw")

    def fail_securitytrails(*args, **kwargs):
        raise AssertionError("SecurityTrails must not be queried without an API key")

    monkeypatch.setattr("modules.passive_dns._query_mnemonic", fake_mnemonic)
    monkeypatch.setattr("modules.passive_dns._query_securitytrails", fail_securitytrails)

    result = await plugin.run(context, tmp_path / "unused")
    assert result.success


@pytest.mark.asyncio
async def test_securitytrails_failure_does_not_erase_mnemonic_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, settings = _context(tmp_path)
    settings.securitytrails_api_key = "test-key"
    plugin = PassiveDnsPlugin(settings)

    def fake_mnemonic(host, timeout, user_agent, proxy_url):
        return ({IP}, None, None, "raw")

    def fake_securitytrails(host, api_key, timeout, user_agent, proxy_url):
        raise TimeoutError("simulated securitytrails outage")

    monkeypatch.setattr("modules.passive_dns._query_mnemonic", fake_mnemonic)
    monkeypatch.setattr("modules.passive_dns._query_securitytrails", fake_securitytrails)

    result = await plugin.run(context, tmp_path / "unused")

    assert result.success
    records = read_jsonl(context.output_dir / "passive_dns.jsonl")
    for record in records:
        assert record["ip"] == [IP]
        assert record["query_status"] == "ok"
        assert "securitytrails" not in record["providers"]


@pytest.mark.asyncio
async def test_securitytrails_additive_when_it_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, settings = _context(tmp_path)
    settings.securitytrails_api_key = "test-key"
    plugin = PassiveDnsPlugin(settings)
    other_ip = "203.0.113.9"

    def fake_mnemonic(host, timeout, user_agent, proxy_url):
        return ({IP}, None, None, "raw")

    def fake_securitytrails(host, api_key, timeout, user_agent, proxy_url):
        return ({other_ip}, None, None, "raw")

    monkeypatch.setattr("modules.passive_dns._query_mnemonic", fake_mnemonic)
    monkeypatch.setattr("modules.passive_dns._query_securitytrails", fake_securitytrails)

    result = await plugin.run(context, tmp_path / "unused")

    assert result.success
    records = read_jsonl(context.output_dir / "passive_dns.jsonl")
    for record in records:
        assert set(record["ip"]) == {IP, other_ip}
        assert set(record["providers"]) == {"mnemonic", "securitytrails"}


def test_mnemonic_response_shape_parses_only_tlp_white_a_records() -> None:
    payload = {
        "responseCode": 200,
        "data": [
            {
                "query": "virusinspector.top.",
                "answer": "34.75.127.116",
                "rrtype": "a",
                "tlp": "white",
                "firstSeenTimestamp": 1749427200000,
                "lastSeenTimestamp": 1756512000000,
            },
            {
                "query": "virusinspector.top.",
                "answer": "10.0.0.1",
                "rrtype": "a",
                "tlp": "amber",
                "firstSeenTimestamp": 1,
                "lastSeenTimestamp": 2,
            },
            {
                "query": "virusinspector.top.",
                "answer": "2001:db8::1",
                "rrtype": "aaaa",
                "tlp": "white",
                "firstSeenTimestamp": 1,
                "lastSeenTimestamp": 2,
            },
        ],
    }

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, _n):
            return json.dumps(payload).encode("utf-8")

    import modules.passive_dns as passive_dns_module

    def fake_open_url(request, *, timeout, proxy_url=None):
        return _FakeResponse()

    orig = passive_dns_module.open_url
    passive_dns_module.open_url = fake_open_url
    try:
        ips, first_seen, last_seen, raw = passive_dns_module._query_mnemonic(
            "virusinspector.top", 15, "hydra/1.0", None
        )
    finally:
        passive_dns_module.open_url = orig

    assert ips == {"34.75.127.116"}, "only TLP-white A records may surface, never amber/aaaa"
    assert first_seen == "1749427200000"
    assert last_seen == "1756512000000"

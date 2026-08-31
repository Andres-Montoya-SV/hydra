"""Native WHOIS client (`core/collection/whois_client.py`): the referral
chain (IANA -> registry -> registrar) is followed by Hydra itself, with every
hop's resolved IP validated by `core/collection/ssrf.py` before connecting —
replacing the previous system `whois` binary, which made these connections
invisibly, outside any of Hydra's authorization/SSRF checks.

Binding the real WHOIS port (43) requires root, so hop I/O is stubbed at the
`asyncio.open_connection` level — the same convention `modules/asn_lookup.py`'s
own tests already use for the identical `whois.cymru.com:43` problem (see
`tests/test_infrastructure_plugins.py`). The security-relevant logic under
test — `validate_destination_ips_async`'s real SSRF classification — runs
unmodified; only DNS resolution is monkeypatched per-hostname, exactly like
every other DNS-rebinding test in this suite.
"""

from __future__ import annotations

import pytest

from core.collection.whois_client import query_whois_chain


class _FakeStreamWriter:
    def __init__(self) -> None:
        self.written = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakeStreamReader:
    def __init__(self, payload: bytes) -> None:
        self._chunks = [payload, b""]

    async def read(self, _n: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


def _fake_connection_once(payload: bytes):
    """Return an `asyncio.open_connection` stand-in that must be called
    exactly once — a second call means a hop the chain should have refused
    (and never attempted to connect for) was reached anyway."""
    calls = {"count": 0}

    async def _open(_host: str, _port: int):
        calls["count"] += 1
        if calls["count"] > 1:
            raise AssertionError(
                "asyncio.open_connection called a second time — a blocked "
                "hop must never actually connect"
            )
        return _FakeStreamReader(payload), _FakeStreamWriter()

    return _open


@pytest.mark.asyncio
async def test_referral_chain_stops_when_registry_hop_resolves_to_private_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IANA (hop 1) succeeds and refers to a registry hostname; that registry
    hostname resolves to a private IP. The chain must stop there: hop 2 is
    recorded as refused, no connection is attempted for it, and there is no
    hop 3 (registrar) at all — the chain never gets that far."""
    iana_response = b"whois:        whois.private-registry.test\n"

    async def fake_resolve(host: str) -> list[str]:
        if host == "whois.iana.org":
            return ["192.0.2.10"]
        if host == "whois.private-registry.test":
            return ["10.1.2.3"]
        raise AssertionError(f"unexpected hop attempted: {host}")

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", fake_resolve)
    monkeypatch.setattr(
        "core.collection.whois_client.asyncio.open_connection",
        _fake_connection_once(iana_response),
    )

    result = await query_whois_chain("example.test", timeout=5)

    assert len(result.hops) == 2
    assert result.hops[0].host == "whois.iana.org"
    assert result.hops[0].allowed is True
    assert result.hops[1].host == "whois.private-registry.test"
    assert result.hops[1].allowed is False
    assert result.hops[1].reason == "blocked_range:10.0.0.0/8"
    assert result.blocked is True
    assert result.blocked_reason == "blocked_range:10.0.0.0/8"
    # Hop 1's response text is kept (never discard a legitimate partial
    # observation) — the chain simply never got a registry/registrar block
    # to append after it.
    assert result.raw.strip() == iana_response.decode().strip()


@pytest.mark.asyncio
async def test_referral_chain_stops_when_iana_itself_resolves_to_private_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The very first hop can be refused too — no partial data at all in
    that case, and no connection of any kind is attempted."""

    async def fake_resolve(_host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", fake_resolve)
    monkeypatch.setattr(
        "core.collection.whois_client.asyncio.open_connection",
        _fake_connection_once(b"unused"),
    )

    result = await query_whois_chain("example.test", timeout=5)

    assert len(result.hops) == 1
    assert result.hops[0].allowed is False
    assert result.hops[0].reason == "blocked_range:127.0.0.0/8"
    assert result.blocked is True
    assert result.raw == ""


@pytest.mark.asyncio
async def test_referral_chain_follows_registry_to_registrar_when_all_hops_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normal case: IANA refers to a registry, the registry's response names
    a distinct registrar WHOIS server, and every hop resolves to a public IP
    — all three hops are queried and their raw text concatenated root-first,
    matching the shape `modules/whois.py`'s existing parsing expects."""
    responses = {
        "whois.iana.org": b"whois:        whois.fake-registry.test\n",
        "whois.fake-registry.test": (
            b"Domain Name: EXAMPLE.TEST\n" b"Registrar WHOIS Server: whois.fake-registrar.test\n"
        ),
        "whois.fake-registrar.test": (
            b"Domain Name: EXAMPLE.TEST\nRegistrar: Fake Registrar LLC\n"
        ),
    }
    hosts_connected: list[str] = []

    async def fake_resolve(host: str) -> list[str]:
        assert host in responses, f"unexpected hop: {host}"
        return ["192.0.2.10"]

    # `_query_hop` connects to the resolved IP, not the hostname, so the
    # fixture can't dispatch on `host` here — hops are queried strictly in
    # order (IANA -> registry -> registrar), so a fixed response sequence is
    # equivalent to dispatching on hostname for this test.
    call_order: list[bytes] = list(responses.values())

    async def _sequenced_connection(_host: str, _port: int):
        payload = call_order.pop(0)
        hosts_connected.append(payload.decode())
        return _FakeStreamReader(payload), _FakeStreamWriter()

    monkeypatch.setattr("core.collection.ssrf.resolve_hostname_async", fake_resolve)
    monkeypatch.setattr(
        "core.collection.whois_client.asyncio.open_connection", _sequenced_connection
    )

    result = await query_whois_chain("example.test", timeout=5)

    assert len(result.hops) == 3
    assert [hop.host for hop in result.hops] == [
        "whois.iana.org",
        "whois.fake-registry.test",
        "whois.fake-registrar.test",
    ]
    assert all(hop.allowed for hop in result.hops)
    assert result.blocked is False
    assert "Fake Registrar LLC" in result.raw
    assert "Registrar WHOIS Server" in result.raw
    # Root-first ordering preserved.
    assert result.raw.index("whois.fake-registry.test") < result.raw.index("Fake Registrar LLC")

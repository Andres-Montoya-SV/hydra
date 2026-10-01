"""Productization Phase 11a: the well-known-file domain verification is a
server-side fetch of a caller-supplied domain, so it goes through the same
SSRF gate as webhook deliveries."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import pytest
from _webhook_test_server import (
    WebhookTestHandler,
    reset_webhook_test_state,
    start_webhook_test_server,
    stop_webhook_test_server,
)

import api.webhooks as webhooks_module
import core.collection.ssrf as ssrf_module
from api.domain_verification import verify_well_known_file
from api.webhooks import PinnedResponse, get_pinned


def _resolving_to(monkeypatch: pytest.MonkeyPatch, *addresses: str) -> None:
    async def resolve(hostname: str) -> list[str]:
        del hostname
        return list(addresses)

    monkeypatch.setattr(ssrf_module, "resolve_hostname_async", resolve)


def _no_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    async def refuse(**_: Any) -> PinnedResponse:
        raise AssertionError("a refused destination must never be fetched")

    monkeypatch.setattr(webhooks_module, "get_pinned", refuse)


class TestRefusedDestinations:
    @pytest.mark.parametrize(
        "addresses",
        [
            ("127.0.0.1",),
            ("169.254.169.254",),  # cloud metadata
            ("10.0.0.5",),
            ("192.168.1.10",),
            ("::1",),
            ("93.184.216.34", "10.0.0.5"),  # one private address is enough to refuse
        ],
    )
    def test_a_domain_resolving_to_a_non_public_address_is_never_fetched(
        self, monkeypatch: pytest.MonkeyPatch, addresses: tuple[str, ...]
    ) -> None:
        _resolving_to(monkeypatch, *addresses)
        _no_fetch(monkeypatch)
        ok, detail = asyncio.run(verify_well_known_file("victim.example", "tok"))
        assert not ok and "refused" in detail.lower()


class TestPinnedFetch:
    @pytest.fixture
    def fetched(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[list[dict[str, Any]]]:
        calls: list[dict[str, Any]] = []

        async def allow(url: str) -> tuple[bool, str, str]:
            del url
            return True, "", "93.184.216.34"

        def answer(status: int | None, body: bytes, error: str = "") -> None:
            async def fake(**kwargs: Any) -> PinnedResponse:
                calls.append(kwargs)
                return PinnedResponse(status, body, error, None)

            monkeypatch.setattr(webhooks_module, "get_pinned", fake)

        monkeypatch.setattr(webhooks_module, "validate_webhook_destination", allow)
        self.answer = answer
        yield calls

    def test_matching_token_from_the_pinned_address(self, fetched: list[dict[str, Any]]) -> None:
        self.answer(200, b"tok\n")
        ok, _ = asyncio.run(verify_well_known_file("Example.COM", "tok"))
        assert ok
        assert fetched[0]["connect_ip"] == "93.184.216.34"
        assert fetched[0]["hostname"] == "example.com"
        assert fetched[0]["url"].startswith("https://example.com/.well-known/")

    @pytest.mark.parametrize(
        ("status", "body", "error", "expected"),
        [
            (200, b"other", "", "does not match"),
            (404, b"", "", "HTTP 404"),
            (None, b"", "ConnectError: refused", "Could not reach"),
        ],
    )
    def test_failures(
        self,
        fetched: list[dict[str, Any]],
        status: int | None,
        body: bytes,
        error: str,
        expected: str,
    ) -> None:
        self.answer(status, body, error)
        ok, detail = asyncio.run(verify_well_known_file("example.com", "tok"))
        assert not ok and expected in detail


class TestGetPinned:
    @pytest.fixture
    def server(self) -> Iterator[int]:
        httpd, port, thread, tmp_dir = start_webhook_test_server()
        try:
            yield port
        finally:
            stop_webhook_test_server(httpd, thread, tmp_dir)

    def test_reads_at_most_max_bytes(self, server: int) -> None:
        reset_webhook_test_state(body=b"x" * 100_000)
        response = asyncio.run(
            get_pinned(
                url=f"https://victim.example:{server}/.well-known/f.txt",
                connect_ip="127.0.0.1",
                hostname="victim.example",
                max_bytes=4096,
                verify=False,  # the local server's certificate is self-signed
            )
        )
        assert response.status == 200 and len(response.content) == 4096
        request = WebhookTestHandler.requests[0]
        assert request["path"] == "/.well-known/f.txt"
        assert request["headers"]["Host"] == "victim.example"

    def test_does_not_follow_redirects(self, server: int) -> None:
        reset_webhook_test_state(status=302, body=b"")
        response = asyncio.run(
            get_pinned(
                url=f"https://victim.example:{server}/x",
                connect_ip="127.0.0.1",
                hostname="victim.example",
                max_bytes=10,
                verify=False,
            )
        )
        assert response.status == 302 and len(WebhookTestHandler.requests) == 1

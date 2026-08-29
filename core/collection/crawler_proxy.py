"""Local scope-enforcing forward proxy for crawlers Hydra cannot gate by input file alone.

Katana, hakrawler, and nuclei each internally discover and request additional
URLs — chased redirects, crawled links, OOB callbacks — once launched with a
single authorized seed. Feeding them an authorized `-list`/`-l` file only
gates what Hydra *hands* them; it does nothing about what they decide to
request next on their own. All three support `-proxy`.

`ScopeEnforcingProxy` is a minimal local HTTP/HTTPS forward proxy: for every
request it receives, it authorizes the destination host against
`CollectionScope` *before* connecting anywhere. An unauthorized destination
gets `403` (plain HTTP) or a refused `CONNECT` (HTTPS) and the proxy never
opens a socket to it. An authorized destination is transparently forwarded —
for `CONNECT` this is a byte-for-byte TCP splice with no TLS interception
(no certificate is presented, no content is inspected; the tunnel is
authorized by the `CONNECT` target host, not by decrypting it).

This is real containment for exactly what it covers — TCP connections these
three tools would otherwise open directly. It is not a claim of universal
process-level network confinement: a tool that ignores its configured proxy
entirely (a bug, or a raw-socket path bypassing its own HTTP client) is
outside what an application-level proxy can see. See docs/FINAL_SECURITY_AUDIT.md
for the boundary this does and does not draw.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import urlparse

from core.intel.scope import CollectionScope, allows_active_collection
from core.logger import get_logger

logger = get_logger("crawler_proxy")

_CONNECT_TIMEOUT = 10.0
_READ_CHUNK = 65536


@dataclass
class DeniedConnection:
    host: str
    capability: str
    method: str


class ScopeEnforcingProxy:
    """One-shot local proxy instance: start, hand `proxy_url` to a subprocess, stop."""

    def __init__(
        self,
        scope: CollectionScope | None,
        *,
        capability: str,
        host: str = "127.0.0.1",
    ) -> None:
        self.scope = scope
        self.capability = capability
        self.host = host
        self._server: asyncio.AbstractServer | None = None
        self.port = 0
        self.denied: list[DeniedConnection] = []
        self.allowed_hosts: list[str] = []

    @property
    def proxy_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host, 0)
        sockets = self._server.sockets or []
        if not sockets:
            raise RuntimeError("ScopeEnforcingProxy failed to bind a listening socket")
        self.port = sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        try:
            await self._server.wait_closed()
        except Exception:
            logger.debug("crawler_proxy: error while closing server socket", exc_info=True)
        self._server = None

    async def __aenter__(self) -> ScopeEnforcingProxy:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    def _authorized(self, host: str) -> bool:
        if not host or self.scope is None:
            return False
        try:
            return allows_active_collection(host, self.scope)
        except Exception:
            # A bug evaluating scope must block, never fall open.
            logger.warning(
                "crawler_proxy: authorization check raised for %s; denying (fail closed)",
                host,
                exc_info=True,
            )
            return False

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await self._route(reader, writer)
        except Exception:
            logger.debug("crawler_proxy: connection handling error", exc_info=True)
        finally:
            with _SuppressCloseErrors():
                writer.close()

    async def _route(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request_line = await asyncio.wait_for(reader.readline(), timeout=_CONNECT_TIMEOUT)
        if not request_line:
            return
        try:
            method, target, _version = request_line.decode("latin1").strip().split(" ", 2)
        except ValueError:
            return

        header_lines: list[bytes] = []
        host_header = ""
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=_CONNECT_TIMEOUT)
            if line in (b"\r\n", b"\n", b""):
                break
            header_lines.append(line)
            if line.lower().startswith(b"host:"):
                host_header = line.decode("latin1").split(":", 1)[1].strip()

        if method.upper() == "CONNECT":
            await self._handle_connect(target, writer, reader)
            return

        parsed = urlparse(target if "://" in target else f"http://{host_header}{target}")
        host = parsed.hostname or host_header.split(":")[0]
        port = parsed.port or 80

        if not self._authorized(host):
            self.denied.append(
                DeniedConnection(host=host or "", capability=self.capability, method=method)
            )
            writer.write(
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            return
        self.allowed_hosts.append(host)

        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=_CONNECT_TIMEOUT
            )
        except OSError:
            writer.write(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            return

        try:
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            remote_writer.write(f"{method} {path} HTTP/1.1\r\n".encode("latin1"))
            for line in header_lines:
                remote_writer.write(line)
            remote_writer.write(b"\r\n")
            await remote_writer.drain()
            await self._splice(reader, writer, remote_reader, remote_writer)
        finally:
            with _SuppressCloseErrors():
                remote_writer.close()

    async def _handle_connect(
        self, target: str, writer: asyncio.StreamWriter, reader: asyncio.StreamReader
    ) -> None:
        host, _, port_str = target.rpartition(":")
        port = int(port_str) if port_str.isdigit() else 443
        if not self._authorized(host):
            self.denied.append(
                DeniedConnection(host=host, capability=self.capability, method="CONNECT")
            )
            writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        self.allowed_hosts.append(host)

        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=_CONNECT_TIMEOUT
            )
        except OSError:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return

        try:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            # No TLS interception: from here it's an opaque byte splice. The
            # authorization decision above was made on the CONNECT target
            # host, not on decrypted content.
            await self._splice(reader, writer, remote_reader, remote_writer)
        finally:
            with _SuppressCloseErrors():
                remote_writer.close()

    async def _splice(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
    ) -> None:
        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    chunk = await src.read(_READ_CHUNK)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except Exception:
                logger.debug("crawler_proxy: splice pump ended with an error", exc_info=True)
            finally:
                with _SuppressCloseErrors():
                    dst.close()

        await asyncio.gather(
            pump(client_reader, remote_writer),
            pump(remote_reader, client_writer),
        )


class _SuppressCloseErrors:
    """`writer.close()` on an already-broken pipe raises noise we don't care about."""

    def __enter__(self) -> _SuppressCloseErrors:
        return self

    def __exit__(self, *exc: object) -> bool:
        return True

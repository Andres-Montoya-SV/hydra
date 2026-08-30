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
import base64
from dataclasses import dataclass
from urllib.parse import urlparse

from core.collection.audit import NetworkRequestRecord
from core.intel.authorize import authorize_active_indicator
from core.intel.scope import CollectionScope
from core.logger import get_logger
from core.provenance import utc_now_iso

logger = get_logger("crawler_proxy")

_CONNECT_TIMEOUT = 10.0
_READ_CHUNK = 65536

# Tools/collectors verified live (not just by reading their docs or
# assuming a shared code path is equivalent to being tested) to route every
# outbound connection through this proxy: tests/test_crawler_confinement_live.py
# drives the actual katana/hakrawler binaries against a local redirect chain
# and asserts the unauthorized target's connection counter stays at zero;
# tests/test_httpx_confinement_live.py does the same for the real installed
# httpx binary via `-proxy`; tests/test_browser_confinement_live.py does the
# same for real WebKit via Playwright's launch-time `proxy=` option;
# tests/test_urllib_confinement_live.py does the same for the three built-in
# Python collectors sharing `core/http_probe.py:http_get` (soft404_check,
# param_fuzz, cloud_bucket_enum) — all six cover both ALLOW (destination
# reached) and DENY (destination gets zero connections) directions, including
# a DNS-rebinding scenario where an in-scope *hostname* resolves to a
# private/loopback address. Assuming param_fuzz/cloud_bucket_enum were
# equally verified just because they call the same function as soft404_check
# would itself have been the wrong instinct: writing their dedicated live
# tests surfaced a real, separate bug (see `core/intel/authorize.py:
# _CLOUD_BUCKET_ENUM_OPERATIONS`) that a shared-code-path assumption would
# have missed entirely.
#
# This proxy is an application-level HTTP/HTTPS forward proxy. It has no way
# to stop a process that ignores its proxy configuration and opens a raw
# socket directly — see tests/test_untrusted_network_bypass.py, which proves
# this concretely rather than merely asserting it. Any collector added to
# `modules/_base.py:_crawler_confinement` that is NOT in this set gets an
# explicit `UNTRUSTED_NETWORK_TOOL` warning instead of a silent, unverified
# claim of confinement.
PROXY_VERIFIED_TOOLS = frozenset(
    {
        "katana",
        "hakrawler",
        "nuclei",
        "httpx",
        "browser_probe",
        "soft404_check",
        "param_fuzz",
        "cloud_bucket_enum",
    }
)


@dataclass
class DeniedConnection:
    host: str
    capability: str
    method: str


class ScopeEnforcingProxy:
    """One-shot local proxy instance: start, hand `proxy_url` to a subprocess, stop.

    `upstream_proxy_url`, when set, chains this proxy in front of an
    operator-configured external (typically OPSEC-hiding/rotating) proxy:

        collector -> ScopeEnforcingProxy -> upstream_proxy_url -> Internet

    instead of the collector talking to the external proxy directly. Every
    destination still passes `_authorize_with_reason` (scope + this proxy's
    own best-effort SSRF check) *before* Hydra ever forwards a CONNECT/GET to
    the upstream proxy — an unauthorized destination is refused here and
    never reaches the external proxy at all. What this does NOT provide once
    chained: the destination-IP pinning `_authorize_with_reason` normally
    guarantees. The upstream proxy resolves the target hostname itself, from
    its own network location — Hydra cannot observe or control that
    resolution, so the DNS-rebinding/TOCTOU protection this proxy provides in
    its normal (unchained) mode does not extend past the upstream hop. This
    is a structural property of using an external proxy at all, not a bug:
    Hydra's own socket only ever touches the configured upstream proxy in
    this mode, never the target directly.
    """

    def __init__(
        self,
        scope: CollectionScope | None,
        *,
        capability: str,
        host: str = "127.0.0.1",
        upstream_proxy_url: str | None = None,
    ) -> None:
        self.scope = scope
        self.capability = capability
        self.host = host
        self.upstream_proxy_url = upstream_proxy_url
        self._server: asyncio.AbstractServer | None = None
        self.port = 0
        self.denied: list[DeniedConnection] = []
        self.allowed_hosts: list[str] = []
        # Durable audit trail (core/collection/audit.py) — every decision,
        # ALLOW and DENY alike, for persistence into intel_network_requests.
        self.audit: list[NetworkRequestRecord] = []

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

    async def _authorize_with_reason(
        self, host: str, *, indicator: str | None = None
    ) -> tuple[bool, str, str]:
        """Return (allowed, reason, connect_ip).

        Two independent gates, in order: (1) is `host` a hostname/IP the
        operator's `CollectionScope` authorizes at all (unchanged from
        before this check existed); (2) does `host` actually resolve to a
        destination outside the private/loopback/link-local/CGNAT/metadata
        blocklist (`core/collection/ssrf.py`), unless
        `scope.allow_private_network_targets` opts in. `connect_ip` is the
        resolved address validated by gate (2) — callers must connect to
        THIS address, not re-resolve `host` a second time at connect time,
        or DNS could legitimately answer differently between the two calls
        (rebinding) and silently reach an address gate (2) never actually
        checked.

        `indicator`, when given, is the full absolute URL authorized instead
        of the bare `host` — this is what lets a SCOPE_FILE path exclusion
        (`!domain/path-glob`) apply to plain-HTTP crawler traffic, where the
        path is actually visible to this proxy. For `CONNECT` (HTTPS) this is
        never passed: the path is inside the encrypted tunnel this proxy
        splices without TLS interception, so only the host-level check
        applies there — the same pre-existing, honestly-documented limit as
        every other scope check against a `CONNECT` target.
        """
        if not host:
            return False, "empty_host", ""
        if self.scope is None:
            return False, "missing_collection_scope", ""
        try:
            # `authorize_active_indicator` directly, with this proxy's own
            # `capability` as the operation — NOT `allows_active_collection`,
            # which hardcodes a generic "active_collection" operation label
            # internally. That mismatch was a real bug: cloud_bucket_enum's
            # own pre-check authorizes a generated bucket hostname via the
            # explicit cloud-collection opt-in (operation="cloud_bucket_enum"),
            # but the proxy's re-check using the generic label never matched
            # that special case, fell through to ordinary registrable-domain
            # scope matching (which a generated bucket hostname can never
            # pass), and denied every candidate with a bare 403 — which the
            # plugin's own classifier then misread as "bucket exists, access
            # denied" for GCS/Azure. See `core/intel/authorize.py:
            # _CLOUD_BUCKET_ENUM_OPERATIONS`.
            result = authorize_active_indicator(
                indicator or host, self.scope, self.capability, "confinement_proxy_recheck"
            )
            allowed = result.allowed
        except Exception:
            # A bug evaluating scope must block, never fall open.
            logger.warning(
                "crawler_proxy: authorization check raised for %s; denying (fail closed)",
                host,
                exc_info=True,
            )
            return False, "authorization_error", ""
        if not allowed:
            return False, "out_of_scope", ""

        from core.collection.ssrf import validate_destination_ips_async

        decision = await validate_destination_ips_async(
            host, allow_private_network_targets=self.scope.allow_private_network_targets
        )
        if not decision.allowed:
            return False, decision.reason, ""
        return True, "in_scope", decision.connect_ip

    async def _open_upstream_tunnel(
        self, target_host: str, target_port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """CONNECT through `self.upstream_proxy_url` to `target_host:target_port`.

        Raises `OSError` on any failure (connection refused, non-2xx
        response) — callers must treat that exactly like a direct-connect
        failure (502 to the client), never as success.
        """
        upstream = urlparse(self.upstream_proxy_url)
        upstream_host = upstream.hostname or ""
        upstream_port = upstream.port or (443 if upstream.scheme == "https" else 80)
        reader, writer = await asyncio.open_connection(upstream_host, upstream_port)
        try:
            request_lines = [f"CONNECT {target_host}:{target_port} HTTP/1.1"]
            request_lines.append(f"Host: {target_host}:{target_port}")
            if upstream.username:
                credentials = f"{upstream.username}:{upstream.password or ''}"
                token = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
                request_lines.append(f"Proxy-Authorization: Basic {token}")
            request_lines.append("")
            request_lines.append("")
            writer.write("\r\n".join(request_lines).encode("latin1"))
            await writer.drain()
            status_line = await asyncio.wait_for(reader.readline(), timeout=_CONNECT_TIMEOUT)
            status_parts = status_line.decode("latin1", errors="replace").strip().split(" ")
            status_code = status_parts[1] if len(status_parts) > 1 else ""
            if status_code != "200":
                raise OSError(
                    f"upstream proxy CONNECT to {target_host}:{target_port} refused: "
                    f"{status_line.decode('latin1', errors='replace').strip()}"
                )
            # Drain the rest of the upstream proxy's CONNECT response headers.
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=_CONNECT_TIMEOUT)
                if line in (b"\r\n", b"\n", b""):
                    break
        except Exception:
            with _SuppressCloseErrors():
                writer.close()
            raise
        return reader, writer

    def _record(
        self,
        *,
        method: str,
        host: str,
        port: int,
        allowed: bool,
        reason: str,
        resolved_ip: str = "",
    ) -> None:
        self.audit.append(
            NetworkRequestRecord(
                collector=self.capability,
                capability=self.capability,
                method=method,
                url=f"{host}:{port}" if host else "",
                normalized_hostname=host,
                resolved_ip=resolved_ip,
                port=port,
                decision="ALLOW" if allowed else "DENY",
                reason=reason,
                network_attempted=allowed,
                observed_at=utc_now_iso(),
            )
        )

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

        absolute_target = target if "://" in target else f"http://{host_header}{target}"
        parsed = urlparse(absolute_target)
        host = parsed.hostname or host_header.split(":")[0]
        port = parsed.port or 80

        # Plain HTTP: the path is visible to this proxy (unlike CONNECT), so
        # pass the full absolute URL — this is what lets a SCOPE_FILE path
        # exclusion apply here, not just the host.
        allowed, reason, connect_ip = await self._authorize_with_reason(
            host, indicator=absolute_target
        )
        self._record(
            method=method,
            host=host or "",
            port=port,
            allowed=allowed,
            reason=reason,
            resolved_ip=connect_ip,
        )
        if not allowed:
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
            if self.upstream_proxy_url:
                # Chained mode: forward to the upstream (external OPSEC)
                # proxy using the same absolute-URI request line a client
                # would send it directly — Hydra already authorized `host`
                # above; the upstream proxy resolves and connects from its
                # own network location (see class docstring for exactly what
                # is and isn't validated in this mode).
                upstream = urlparse(self.upstream_proxy_url)
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(upstream.hostname, upstream.port or 80),
                    timeout=_CONNECT_TIMEOUT,
                )
            else:
                # Connect to the IP already resolved and validated above,
                # not a fresh `host` lookup — closes the DNS-rebinding/
                # TOCTOU gap where a second resolution could legitimately
                # answer differently than the one just checked.
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_ip, port), timeout=_CONNECT_TIMEOUT
                )
        except OSError:
            writer.write(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            return
        self.audit[-1].network_completed = True

        try:
            if self.upstream_proxy_url:
                upstream = urlparse(self.upstream_proxy_url)
                remote_writer.write(f"{method} {absolute_target} HTTP/1.1\r\n".encode("latin1"))
                for line in header_lines:
                    remote_writer.write(line)
                if upstream.username:
                    credentials = f"{upstream.username}:{upstream.password or ''}"
                    token = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
                    remote_writer.write(f"Proxy-Authorization: Basic {token}\r\n".encode("latin1"))
            else:
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
        allowed, reason, connect_ip = await self._authorize_with_reason(host)
        self._record(
            method="CONNECT",
            host=host,
            port=port,
            allowed=allowed,
            reason=reason,
            resolved_ip=connect_ip,
        )
        if not allowed:
            self.denied.append(
                DeniedConnection(host=host, capability=self.capability, method="CONNECT")
            )
            writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        self.allowed_hosts.append(host)

        try:
            if self.upstream_proxy_url:
                # Chained mode: CONNECT through the upstream (external OPSEC)
                # proxy using the ORIGINAL hostname — it resolves and
                # connects from its own network location. Hydra already
                # authorized `host` above by its own scope/SSRF checks; see
                # the class docstring for exactly what this mode does and
                # does not validate (the upstream's own resolution is
                # outside Hydra's visibility, by the nature of using an
                # external proxy at all).
                remote_reader, remote_writer = await self._open_upstream_tunnel(host, port)
            else:
                # Connect to the already-validated IP, not a fresh `host`
                # lookup — see the identical comment in `_route`. The client's
                # own TLS ClientHello (SNI) flows through the splice unchanged,
                # so pinning the TCP connection to this IP is transparent to
                # certificate validation, which happens at the client, not here.
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_ip, port), timeout=_CONNECT_TIMEOUT
                )
        except OSError:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        self.audit[-1].network_completed = True

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

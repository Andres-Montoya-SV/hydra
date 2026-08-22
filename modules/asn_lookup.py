"""ASN and IP ownership enrichment using Team Cymru (no external binaries).

Primary path: TCP bulk WHOIS to ``whois.cymru.com:43`` via
``asyncio.open_connection`` (stdlib sockets only).

Fallback: Team Cymru DNS IP-to-ASN (TXT queries to ``origin.asn.cymru.com`` /
``AS{n}.asn.cymru.com``) using UDP against the system resolvers from
``/etc/resolv.conf``. Some networks accept a TCP connect to :43 but never
deliver WHOIS payloads (empty reads / ``TimeoutError`` with an empty
message) — DNS still works there and needs nothing installed.
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import socket
import struct
from pathlib import Path

from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import read_jsonl, write_jsonl

_CYMRU_WHOIS_HOST = "whois.cymru.com"
_CYMRU_WHOIS_PORT = 43
# Idle gap while reading WHOIS: if the peer never closes, stop and use bytes
# already received (or fail empty) instead of hanging until the outer timeout.
_TCP_READ_IDLE_SECONDS = 5.0


class AsnLookupPlugin(BaseToolPlugin):
    """Enrich resolved IPs through Team Cymru — sockets/DNS only, no binaries."""

    name = "asn_lookup"
    display_name = "ASN Lookup"
    required = False
    external_dependency = False
    stage_order = 32
    produces = ("ips",)
    capability = "asn"
    active_collection = True

    def is_enabled(self) -> bool:
        return self.settings.enable_asn_lookup

    def get_binary_path(self) -> Path:
        return Path("built-in")

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        output_path = self._output_path(context, "asn.jsonl")
        ips = await _collect_ips(context)
        if not ips:
            reason = "skipped: no resolved IPs available"
            context.add_warning(f"ASN Lookup: {reason}")
            self.update_status(
                context,
                ToolStatus.SKIPPED,
                output_lines=0,
                error_message=reason,
            )
            write_jsonl(output_path, [], base_dir=context.output_dir)
            return self._skip(reason)

        self.update_status(context, ToolStatus.RUNNING)
        try:
            records = await asyncio.wait_for(
                _query_cymru(ips),
                timeout=self.settings.asn_lookup_timeout,
            )
        except (TimeoutError, OSError, asyncio.IncompleteReadError, ValueError) as exc:
            detail = _format_exc(
                exc,
                fallback=(
                    f"timed out after {self.settings.asn_lookup_timeout}s "
                    f"querying Team Cymru for {len(ips)} IP(s) "
                    f"(TCP whois.cymru.com:43 and DNS IP-to-ASN)"
                ),
            )
            context.add_warning(f"ASN Lookup unavailable: {detail}")
            self.update_status(
                context,
                ToolStatus.COMPLETED,
                output_lines=0,
                error_message=detail,
            )
            write_jsonl(output_path, [], base_dir=context.output_dir)
            return PluginResult(
                success=True,
                output_path=output_path,
                message="ASN service unavailable; scan continued",
            )

        count = write_jsonl(output_path, records, base_dir=context.output_dir)
        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=f"Enriched {count} IP address(es)",
        )


def _format_exc(exc: BaseException, *, fallback: str) -> str:
    """Never return an empty failure reason.

    ``TimeoutError()`` / ``asyncio.TimeoutError()`` stringify to ``""``, which
    produced the useless warning ``ASN Lookup unavailable: `` in run
    ``20260806_185622``. Always include the exception type, and a concrete
    fallback when the exception itself has no message.
    """
    text = str(exc).strip()
    name = type(exc).__name__
    if text:
        return f"{name}: {text}"
    return f"{name}: {fallback}"


async def _collect_ips(context: PipelineContext) -> list[str]:
    ips: set[str] = set()
    if context.registry:
        for host in context.registry.values():
            ips.update(host.ips)

    if not ips:
        for record in read_jsonl(context.output_dir / "dnsx_records.jsonl"):
            for key in ("a", "aaaa"):
                values = record.get(key, [])
                if isinstance(values, list):
                    ips.update(str(value) for value in values)

    # dnsx sometimes writes an empty dnsx_records.jsonl while still producing
    # resolved.txt via its hostname fallback (seen on run 20260806_183325).
    # Resolve those hostnames locally so ASN enrichment is not silently skipped
    # when we clearly have live targets.
    if not ips and context.resolved:
        ips.update(await _resolve_hostnames(context.resolved))

    valid: list[str] = []
    for value in ips:
        try:
            valid.append(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return sorted(set(valid))


async def _resolve_hostnames(hostnames: list[str]) -> set[str]:
    ips: set[str] = set()
    loop = asyncio.get_running_loop()
    for hostname in hostnames:
        host = (hostname or "").strip().rstrip(".")
        if not host:
            continue
        try:
            infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError:
            continue
        for info in infos:
            sockaddr = info[4]
            if sockaddr:
                ips.add(str(sockaddr[0]))
    return ips


async def _query_cymru(ips: list[str]) -> list[dict[str, str]]:
    """Prefer TCP bulk WHOIS; fall back to DNS IP-to-ASN on empty/timeout."""
    tcp_error: BaseException | None = None
    try:
        records = await _query_cymru_tcp(ips)
        if records:
            return records
        tcp_error = OSError(
            "whois.cymru.com:43 returned no parseable ASN rows for " + ", ".join(ips[:5])
        )
    except (TimeoutError, OSError, asyncio.IncompleteReadError) as exc:
        tcp_error = exc

    try:
        records = await _query_cymru_dns(ips)
    except (TimeoutError, OSError, ValueError) as dns_exc:
        tcp_detail = _format_exc(tcp_error, fallback="TCP WHOIS failed") if tcp_error else "n/a"
        dns_detail = _format_exc(dns_exc, fallback="DNS IP-to-ASN failed")
        raise OSError(
            f"Team Cymru lookup failed via TCP ({tcp_detail}) and DNS ({dns_detail})"
        ) from dns_exc

    if records:
        return records
    tcp_detail = _format_exc(tcp_error, fallback="TCP WHOIS failed") if tcp_error else "n/a"
    raise OSError(f"Team Cymru returned no ASN data via TCP ({tcp_detail}) or DNS IP-to-ASN")


async def _query_cymru_tcp(ips: list[str]) -> list[dict[str, str]]:
    """Bulk WHOIS over a plain TCP socket to whois.cymru.com:43."""
    reader, writer = await asyncio.open_connection(_CYMRU_WHOIS_HOST, _CYMRU_WHOIS_PORT)
    try:
        payload = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
        writer.write(payload.encode("ascii"))
        await writer.drain()
        # Half-close write so servers that wait for end-of-query can reply.
        if writer.can_write_eof():
            writer.write_eof()

        chunks: list[bytes] = []
        total = 0
        while total < 8 * 1024 * 1024:
            try:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=_TCP_READ_IDLE_SECONDS)
            except TimeoutError:
                # Idle — peer kept the connection open without more data.
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        response = b"".join(chunks)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    if not response.strip():
        raise OSError(
            f"{_CYMRU_WHOIS_HOST}:{_CYMRU_WHOIS_PORT} accepted TCP but returned "
            "no WHOIS data (empty response)"
        )
    return _parse_cymru_whois(response.decode("utf-8", errors="replace"))


def _parse_cymru_whois(text: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(("Bulk mode", "AS ")):
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 7 or not parts[1]:
            continue
        records.append(
            {
                "asn": parts[0],
                "ip": parts[1],
                "bgp_prefix": parts[2],
                "country": parts[3],
                "registry": parts[4],
                "allocated": parts[5],
                "as_name": parts[6],
            }
        )
    return records


async def _query_cymru_dns(ips: list[str]) -> list[dict[str, str]]:
    """Team Cymru DNS IP-to-ASN mapping (TXT), stdlib UDP only."""
    nameservers = _system_nameservers()
    if not nameservers:
        raise OSError("no system DNS nameservers available for Cymru DNS fallback")

    records: list[dict[str, str]] = []
    for ip in ips:
        origin_name = _origin_dns_name(ip)
        origin_txts = await _dns_txt(origin_name, nameservers)
        if not origin_txts:
            continue
        # "26347 | 173.236.128.0/17 | US | arin | 2010-03-30"
        origin_parts = [p.strip() for p in origin_txts[0].split("|")]
        if len(origin_parts) < 5 or not origin_parts[0]:
            continue
        asn = origin_parts[0]
        as_name = ""
        as_txts = await _dns_txt(f"AS{asn}.asn.cymru.com", nameservers)
        if as_txts:
            # "26347 | US | arin | 2002-08-28 | DREAMHOST-AS - New Dream Network, LLC, US"
            as_parts = [p.strip() for p in as_txts[0].split("|")]
            if len(as_parts) >= 5:
                as_name = as_parts[4]
        records.append(
            {
                "asn": asn,
                "ip": ip,
                "bgp_prefix": origin_parts[1],
                "country": origin_parts[2],
                "registry": origin_parts[3],
                "allocated": origin_parts[4],
                "as_name": as_name,
            }
        )
    return records


def _origin_dns_name(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _system_nameservers() -> list[str]:
    servers: list[str] = []
    try:
        for line in Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                candidate = parts[1]
                try:
                    # Prefer IPv4 resolvers for the simple AF_INET UDP path.
                    if ipaddress.ip_address(candidate).version == 4:
                        servers.append(candidate)
                except ValueError:
                    continue
    except OSError:
        pass
    # Last-resort public resolvers when resolv.conf is empty/unusable.
    for fallback in ("1.1.1.1", "8.8.8.8"):
        if fallback not in servers:
            servers.append(fallback)
    return servers


async def _dns_txt(name: str, nameservers: list[str]) -> list[str]:
    last_error: BaseException | None = None
    for server in nameservers:
        try:
            return await _dns_txt_once(name, server)
        except (TimeoutError, OSError) as exc:
            last_error = exc
            continue
    if last_error:
        raise OSError(
            f"DNS TXT query for {name} failed on all resolvers: "
            f"{_format_exc(last_error, fallback='no response')}"
        ) from last_error
    return []


async def _dns_txt_once(name: str, server: str, *, timeout: float = 4.0) -> list[str]:
    query, tid = _build_dns_txt_query(name)
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_sendto(sock, query, (server, 53))
        data, _addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout=timeout)
    finally:
        sock.close()
    return _parse_dns_txt_answers(data, tid)


def _build_dns_txt_query(name: str) -> tuple[bytes, int]:
    tid = random.randint(0, 65535)  # nosec B311  # DNS query id, not cryptography
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)  # RD=1
    qname = (
        b"".join(
            bytes([len(label)]) + label.encode("ascii") for label in name.strip(".").split(".")
        )
        + b"\x00"
    )
    question = qname + struct.pack(">HH", 16, 1)  # TXT IN
    return header + question, tid


def _parse_dns_txt_answers(response: bytes, tid: int) -> list[str]:
    if len(response) < 12:
        return []
    rtid, _flags, _qd, an_count, _ns, _ar = struct.unpack(">HHHHHH", response[:12])
    if rtid != tid or an_count == 0:
        return []

    index = 12
    # Skip question section.
    index = _skip_dns_name(response, index)
    index += 4  # qtype + qclass

    texts: list[str] = []
    for _ in range(an_count):
        if index >= len(response):
            break
        index = _skip_dns_name(response, index)
        if index + 10 > len(response):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", response[index : index + 10])
        index += 10
        rdata = response[index : index + rdlen]
        index += rdlen
        if rtype != 16:
            continue
        parts: list[str] = []
        cursor = 0
        while cursor < len(rdata):
            length = rdata[cursor]
            cursor += 1
            parts.append(rdata[cursor : cursor + length].decode("utf-8", errors="replace"))
            cursor += length
        texts.append("".join(parts))
    return texts


def _skip_dns_name(buf: bytes, index: int) -> int:
    while index < len(buf):
        length = buf[index]
        if length == 0:
            return index + 1
        if length & 0xC0 == 0xC0:  # compression pointer
            return index + 2
        index += 1 + length
    return index

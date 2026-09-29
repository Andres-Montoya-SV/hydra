"""Minimal MaxMind DB (.mmdb) writer for tests — deliberately NOT
`conftest.py`, same convention as tests/_verified_account.py.

Builds a real, spec-conformant IPv4 database holding ONE network, so geo
tests exercise the genuine `maxminddb` reader on a genuine file rather
than a mock — and without shipping third-party database data. Supports only
what the tests need: maps, UTF-8 strings, doubles, unsigned integers,
arrays. Spec: https://maxmind.github.io/MaxMind-DB/
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

_METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


class _UInt(int):
    """An unsigned integer with an explicit MaxMind type. libmaxminddb (the
    C reader) checks metadata field types strictly — e.g. `build_epoch` must
    be uint64 and `record_size` uint16 — so width can't be inferred."""

    type_id = 6


class U16(_UInt):
    type_id = 5


class U32(_UInt):
    type_id = 6


class U64(_UInt):
    type_id = 9


def _control(type_id: int, size: int) -> bytes:
    if size >= 29:
        raise ValueError("test writer only supports sizes < 29")
    if type_id <= 7:
        return bytes([(type_id << 5) | size])
    return bytes([size, type_id - 7])  # extended type


def encode(value: object) -> bytes:
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _control(2, len(raw)) + raw
    if isinstance(value, float):
        return _control(3, 8) + struct.pack(">d", value)
    if isinstance(value, dict):
        out = _control(7, len(value))
        for key, item in value.items():
            out += encode(key) + encode(item)
        return out
    if isinstance(value, list):
        return _control(11, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, int):
        type_id = value.type_id if isinstance(value, _UInt) else 6
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
        return _control(type_id, len(raw)) + raw
    raise TypeError(f"unsupported type {type(value).__name__}")


def write_mmdb(
    path: Path, *, network: str, record: dict[str, object], database_type: str, build_epoch: int
) -> None:
    """One IPv4 network mapped to `record`; every other address is absent."""
    net = ipaddress.ip_network(network)
    bits = format(int(net.network_address), "032b")[: net.prefixlen]
    node_count = len(bits)
    tree = b""
    for depth, bit in enumerate(bits):
        # Last node on the path points into the data section (offset 0).
        onward = node_count + 16 if depth == node_count - 1 else depth + 1
        left, right = (onward, node_count) if bit == "0" else (node_count, onward)
        tree += left.to_bytes(3, "big") + right.to_bytes(3, "big")
    metadata = {
        "binary_format_major_version": U16(2),
        "binary_format_minor_version": U16(0),
        "build_epoch": U64(build_epoch),
        "database_type": database_type,
        "description": {"en": "Hydra test database"},
        "ip_version": U16(4),
        "languages": ["en"],
        "node_count": U32(node_count),
        "record_size": U16(24),
    }
    path.write_bytes(tree + b"\x00" * 16 + encode(record) + _METADATA_MARKER + encode(metadata))

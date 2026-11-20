"""Internet checksum helpers (RFC 1071) plus header validators.

Checksum verification is optional in the pipeline because it costs a full pass
over the segment; it defaults to *on for offline files* (where correctness
matters) and *off for live capture* (where the NIC usually already dropped bad
frames and the CPU budget belongs to reassembly).
"""

from __future__ import annotations

import struct

from ..core.model import IPPROTO_TCP, IPPROTO_UDP


def inet_checksum(data: bytes | memoryview, initial: int = 0) -> int:
    """One's-complement checksum; returns the value to place in the field."""
    total = initial
    view = memoryview(data)
    length = len(view)
    if length & 1:
        view = memoryview(bytes(view) + b"\x00")
        length += 1
    # 16-bit words, summed in chunks to keep the Python loop short.
    for (word,) in struct.iter_unpack("!H", view[:length]):
        total += word
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def pseudo_header_v4(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    return src + dst + struct.pack("!BBH", 0, proto, length)


def verify_ipv4_header(header: bytes | memoryview) -> bool:
    return inet_checksum(header) == 0


def verify_transport(buf: bytes | memoryview, *, src: bytes, dst: bytes, proto: int) -> bool:
    """Validate a TCP/UDP checksum given the IP pseudo-header addresses."""
    view = memoryview(buf)
    if proto == IPPROTO_TCP:
        return inet_checksum(view, _pseudo_sum(pseudo_header_v4(src, dst, proto, len(view)))) == 0
    if proto == IPPROTO_UDP:
        return inet_checksum(view, _pseudo_sum(pseudo_header_v4(src, dst, proto, len(view)))) == 0
    return True


def _pseudo_sum(pseudo: bytes) -> int:
    total = 0
    for (word,) in struct.iter_unpack("!H", pseudo):
        total += word
    return total

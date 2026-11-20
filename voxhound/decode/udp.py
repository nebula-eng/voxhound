"""UDP header parsing."""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass(slots=True)
class UdpHeader:
    sport: int
    dport: int
    length: int
    checksum: int


def parse(buf: bytes | memoryview) -> UdpHeader:
    if len(buf) < 8:
        raise ValueError("short UDP header")
    sport, dport, length, checksum = struct.unpack_from("!HHHH", buf, 0)
    return UdpHeader(sport=sport, dport=dport, length=length, checksum=checksum)


def payload_view(buf: bytes | memoryview, hdr: UdpHeader) -> memoryview:
    """Payload bounded by the UDP length field, guarding against jumbo lies."""
    view = memoryview(buf)
    end = min(len(view), hdr.length) if hdr.length >= 8 else len(view)
    return view[8:end]

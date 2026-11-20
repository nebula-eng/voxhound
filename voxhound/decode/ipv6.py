"""IPv6 fixed header plus the extension header chain walk."""

from __future__ import annotations

import struct
from dataclasses import dataclass

EXT_HOP_BY_HOP = 0
EXT_ROUTING = 43
EXT_FRAGMENT = 44
EXT_AH = 51
EXT_ESP = 50
EXT_DEST_OPTS = 60
EXT_MOBILITY = 135
EXT_HIP = 139
EXT_SHIM6 = 140

_EXT_NAMES = {
    EXT_HOP_BY_HOP: "HopByHop",
    EXT_ROUTING: "Routing",
    EXT_FRAGMENT: "Fragment",
    EXT_AH: "AH",
    EXT_DEST_OPTS: "DestOpts",
    EXT_MOBILITY: "Mobility",
    EXT_HIP: "HIP",
    EXT_SHIM6: "Shim6",
}


@dataclass(slots=True)
class IPv6Header:
    traffic_class: int
    flow_label: int
    payload_len: int
    next_header: int
    hop_limit: int
    src: bytes
    dst: bytes
    #: populated when a Fragment extension header was present
    frag_id: int = 0
    frag_offset: int = 0
    more_fragments: bool = False
    has_fragment: bool = False

    @property
    def is_fragment(self) -> bool:
        return self.has_fragment and (self.more_fragments or self.frag_offset > 0)


def format_addr(raw: bytes) -> str:
    """RFC 5952 canonical text form (longest zero run compressed)."""
    groups = [int.from_bytes(raw[i : i + 2], "big") for i in range(0, 16, 2)]
    best_start, best_len = -1, 0
    cur_start, cur_len = -1, 0
    for i, g in enumerate(groups):
        if g == 0:
            if cur_start < 0:
                cur_start, cur_len = i, 1
            else:
                cur_len += 1
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
        else:
            cur_start, cur_len = -1, 0
    hexes = [f"{g:x}" for g in groups]
    if best_len < 2:
        return ":".join(hexes)
    return ":".join(hexes[:best_start]) + "::" + ":".join(hexes[best_start + best_len :])


def parse(buf: bytes | memoryview) -> tuple[IPv6Header, int, memoryview]:
    """Return ``(header, transport_proto, transport_payload)``."""
    if len(buf) < 40:
        raise ValueError("short IPv6 header")
    view = memoryview(buf)
    head = struct.unpack_from("!IHBB", view, 0)
    word0 = head[0]
    version = word0 >> 28
    if version != 6:
        raise ValueError(f"IPv6 parser got version {version}")
    hdr = IPv6Header(
        traffic_class=(word0 >> 20) & 0xFF,
        flow_label=word0 & 0xFFFFF,
        payload_len=head[1],
        next_header=head[2],
        hop_limit=head[3],
        src=bytes(view[8:24]),
        dst=bytes(view[24:40]),
    )
    end = min(len(view), 40 + hdr.payload_len) if hdr.payload_len else len(view)
    offset = 40
    proto = hdr.next_header
    while proto in _EXT_NAMES and proto not in (EXT_AH, EXT_ESP):
        if len(view) < offset + 8:
            raise ValueError("truncated IPv6 extension header")
        if proto == EXT_FRAGMENT:
            nxt, _res, frag_off, ident = struct.unpack_from("!BBHI", view, offset)
            hdr.has_fragment = True
            hdr.frag_offset = (frag_off >> 3) & 0x1FFF
            hdr.more_fragments = bool(frag_off & 0x1)
            hdr.frag_id = ident
            offset += 8
            proto = nxt
            continue
        nxt, hdr_ext_len = struct.unpack_from("!BB", view, offset)
        offset += (hdr_ext_len + 1) * 8
        proto = nxt
    return hdr, proto, view[offset:end]

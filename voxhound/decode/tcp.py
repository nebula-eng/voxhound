"""TCP header and option parsing.

Options are kept in wire order because the order itself is a fingerprint input
(JA4T / p0f): two stacks that advertise the same options in a different order
are different stacks.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

OPT_END = 0
OPT_NOP = 1
OPT_MSS = 2
OPT_WSCALE = 3
OPT_SACK_PERM = 4
OPT_SACK = 5
OPT_TIMESTAMP = 8
OPT_FASTOPEN = 34

OPT_NAMES = {
    OPT_END: "EOL",
    OPT_NOP: "NOP",
    OPT_MSS: "MSS",
    OPT_WSCALE: "WS",
    OPT_SACK_PERM: "SACK_PERM",
    OPT_SACK: "SACK",
    OPT_TIMESTAMP: "TS",
    OPT_FASTOPEN: "TFO",
}


@dataclass(slots=True)
class TcpHeader:
    sport: int
    dport: int
    seq: int
    ack: int
    data_offset: int
    flags: int
    window: int
    checksum: int
    urgent: int
    options: tuple[tuple[int, bytes], ...]

    @property
    def header_len(self) -> int:
        return self.data_offset * 4

    # ---------------------------------------------------------------- accessors
    def option(self, kind: int) -> bytes | None:
        for opt_kind, value in self.options:
            if opt_kind == kind:
                return value
        return None

    @property
    def mss(self) -> int | None:
        raw = self.option(OPT_MSS)
        return struct.unpack("!H", raw)[0] if raw and len(raw) >= 2 else None

    @property
    def window_scale(self) -> int | None:
        raw = self.option(OPT_WSCALE)
        return raw[0] if raw else None

    @property
    def sack_permitted(self) -> bool:
        return self.option(OPT_SACK_PERM) is not None

    @property
    def timestamps(self) -> tuple[int, int] | None:
        raw = self.option(OPT_TIMESTAMP)
        if raw and len(raw) >= 8:
            return struct.unpack("!II", raw[:8])
        return None

    @property
    def fast_open(self) -> bytes | None:
        return self.option(OPT_FASTOPEN)

    def option_signature(self) -> str:
        """p0f-style option string, e.g. ``MSS,NOP,WS,NOP,NOP,SACK_PERM``."""
        parts = [OPT_NAMES.get(kind, f"opt{kind}") for kind, _ in self.options]
        return ",".join(parts)


def parse(buf: bytes | memoryview) -> TcpHeader:
    if len(buf) < 20:
        raise ValueError("short TCP header")
    view = memoryview(buf)
    sport, dport, seq, ack, off_flags, window, checksum, urgent = struct.unpack_from("!HHIIHHHH", view, 0)
    data_offset = (off_flags >> 12) & 0x0F
    flags = off_flags & 0x01FF
    if data_offset < 5:
        raise ValueError("invalid TCP data offset")
    header_len = data_offset * 4
    if len(view) < header_len:
        raise ValueError("truncated TCP options")
    options = _parse_options(view[20:header_len]) if header_len > 20 else ()
    return TcpHeader(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        data_offset=data_offset,
        flags=flags,
        window=window,
        checksum=checksum,
        urgent=urgent,
        options=options,
    )


def _parse_options(blob: memoryview) -> tuple[tuple[int, bytes], ...]:
    """Tolerant walk: a malformed option list truncates rather than raising."""
    out: list[tuple[int, bytes]] = []
    pos = 0
    size = len(blob)
    while pos < size:
        kind = blob[pos]
        if kind == OPT_END:
            out.append((kind, b""))
            break
        if kind == OPT_NOP:
            out.append((kind, b""))
            pos += 1
            continue
        if pos + 1 >= size:
            break
        length = blob[pos + 1]
        if length < 2 or pos + length > size:
            break
        out.append((kind, bytes(blob[pos + 2 : pos + length])))
        pos += length
    return tuple(out)

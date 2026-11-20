"""pcapng reader — blocks, interfaces, time resolution, drop counters."""

from __future__ import annotations

import os
import struct
from collections.abc import Iterator
from typing import BinaryIO

from ..core.model import RawPacket

BT_SHB = 0x0A0D0D0A
BT_IDB = 0x00000001
BT_PB = 0x00000002
BT_SPB = 0x00000003
BT_ISB = 0x00000005
BT_EPB = 0x00000006

_MAX_BLOCK = 64 * 1024 * 1024
_BOM = b"\x4d\x3c\x2b\x1a"


class PcapNgError(ValueError):
    """Malformed pcapng stream."""


class _Interface:
    __slots__ = ("linktype", "snaplen", "ts_divisor", "name", "dropped")

    def __init__(self, linktype: int, snaplen: int) -> None:
        self.linktype = linktype
        self.snaplen = snaplen
        self.ts_divisor = 1_000_000
        self.name = ""
        self.dropped = 0


class PcapNgReader:
    """Streaming pcapng reader."""

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._closed = False
        self.endian = "<"
        self.interfaces: list[_Interface] = []
        self.if_dropped = 0

    @classmethod
    def open(cls, path: str | os.PathLike[str]) -> PcapNgReader:
        return cls(open(path, "rb"))  # noqa: SIM115 - caller owns lifecycle

    @property
    def linktype(self) -> int:
        return self.interfaces[0].linktype if self.interfaces else 1

    # ------------------------------------------------------------------ blocks
    def _read_block(self) -> tuple[int, bytes] | None:
        head = self._stream.read(8)
        if len(head) < 8:
            return None
        if head[:4] == b"\x0a\x0d\x0d\x0a":
            bom = self._stream.read(4)
            if len(bom) < 4:
                return None
            self.endian = "<" if bom == _BOM else ">"
            blen = struct.unpack(self.endian + "I", head[4:8])[0]
            if blen < 28 or blen > _MAX_BLOCK:
                raise PcapNgError(f"bad section header length {blen}")
            if len(self._stream.read(blen - 12)) < blen - 12:
                return None
            self.interfaces = []  # section boundary resets interface numbering
            return BT_SHB, b""
        btype, blen = struct.unpack(self.endian + "II", head)
        if blen < 12 or blen > _MAX_BLOCK or blen % 4:
            raise PcapNgError(f"bad block length {blen} for type 0x{btype:08x}")
        body = self._stream.read(blen - 12)
        trailer = self._stream.read(4)
        if len(body) < blen - 12 or len(trailer) < 4:
            return None
        if struct.unpack(self.endian + "I", trailer)[0] != blen:
            raise PcapNgError("block trailer length mismatch")
        return btype, body

    def _parse_idb(self, body: bytes) -> None:
        linktype, _reserved, snaplen = struct.unpack(self.endian + "HHI", body[:8])
        iface = _Interface(linktype, snaplen or 262_144)
        for code, value in _iter_options(body[8:], self.endian):
            if code == 9 and value:  # if_tsresol
                raw = value[0]
                iface.ts_divisor = (2 ** (raw & 0x7F)) if raw & 0x80 else (10 ** (raw & 0x7F))
            elif code == 2:  # if_name
                iface.name = value.decode("utf-8", "replace")
        self.interfaces.append(iface)

    def _packet(self, iface_id: int, ts_raw: int, caplen: int, origlen: int, data: bytes) -> RawPacket | None:
        if iface_id >= len(self.interfaces):
            return None
        iface = self.interfaces[iface_id]
        return RawPacket(
            ts=ts_raw / iface.ts_divisor if iface.ts_divisor else 0.0,
            data=data[:caplen],
            caplen=caplen,
            wirelen=origlen,
            linktype=iface.linktype,
        )

    def _parse_epb(self, body: bytes) -> RawPacket | None:
        if len(body) < 20:
            return None
        iface_id, ts_high, ts_low, caplen, origlen = struct.unpack(self.endian + "IIIII", body[:20])
        return self._packet(iface_id, (ts_high << 32) | ts_low, caplen, origlen, body[20 : 20 + caplen])

    def _parse_pb(self, body: bytes) -> RawPacket | None:
        """Obsolete Packet Block: iface(2) drops(2) ts_high ts_low caplen origlen."""
        if len(body) < 20:
            return None
        iface_id, _drops, ts_high, ts_low, caplen, origlen = struct.unpack(self.endian + "HHIIII", body[:20])
        return self._packet(iface_id, (ts_high << 32) | ts_low, caplen, origlen, body[20 : 20 + caplen])

    def _parse_spb(self, body: bytes) -> RawPacket | None:
        if len(body) < 4:
            return None
        origlen = struct.unpack(self.endian + "I", body[:4])[0]
        caplen = min(origlen, len(body) - 4)
        return self._packet(0, 0, caplen, origlen, body[4 : 4 + caplen])

    def _parse_isb(self, body: bytes) -> None:
        if len(body) < 12:
            return
        iface_id = struct.unpack(self.endian + "I", body[:4])[0]
        if iface_id >= len(self.interfaces):
            return
        for code, value in _iter_options(body[12:], self.endian):
            if code == 4 and len(value) >= 8:  # isb_ifdrop
                self.interfaces[iface_id].dropped = struct.unpack(self.endian + "Q", value[:8])[0]
                self.if_dropped += self.interfaces[iface_id].dropped

    # ------------------------------------------------------------------ iteration
    def __iter__(self) -> Iterator[RawPacket]:
        last_ts = 0.0
        while True:
            block = self._read_block()
            if block is None:
                return
            btype, body = block
            if btype == BT_EPB:
                pkt = self._parse_epb(body)
            elif btype == BT_IDB:
                self._parse_idb(body)
                continue
            elif btype == BT_SPB:
                pkt = self._parse_spb(body)
            elif btype == BT_PB:
                pkt = self._parse_pb(body)
            elif btype == BT_ISB:
                self._parse_isb(body)
                continue
            else:
                continue
            if pkt is not None:
                if pkt.ts == 0.0:
                    pkt.ts = last_ts  # SPB carries no timestamp
                else:
                    last_ts = pkt.ts
                yield pkt

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._stream.close()

    def __enter__(self) -> PcapNgReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _iter_options(blob: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
    pos = 0
    size = len(blob)
    while pos + 4 <= size:
        code, length = struct.unpack(endian + "HH", blob[pos : pos + 4])
        pos += 4
        if code == 0:
            return
        value = blob[pos : pos + length]
        pos += (length + 3) & ~3
        yield code, value

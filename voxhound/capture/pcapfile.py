"""Classic libpcap file format: reader and writer.

Both byte orders and both timestamp resolutions (micro/nanosecond) are handled.
The reader yields :class:`~voxhound.core.model.RawPacket` objects and never
loads a whole file, so a 4 GiB capture streams through in constant memory.
"""

from __future__ import annotations

import io
import os
import struct
from collections.abc import Iterator
from typing import BinaryIO

from ..core.model import RawPacket

MAGIC_USEC_LE = 0xA1B2C3D4
MAGIC_USEC_BE = 0xD4C3B2A1
MAGIC_NSEC_LE = 0xA1B23C4D
MAGIC_NSEC_BE = 0x4D3CB2A1

_GLOBAL_HDR = struct.Struct("<IHHiIII")  # magic, vmaj, vmin, thiszone, sigfigs, snaplen, network
_REC_HDR = struct.Struct("<IIII")  # ts_sec, ts_frac, incl_len, orig_len
_REC_HDR_BE = struct.Struct(">IIII")

MAX_SNAPLEN = 262_144


class PcapError(ValueError):
    """Raised when a file is not a valid classic pcap stream."""


class PcapReader:
    """Streaming reader for ``.pcap``/``.cap`` files or file-like objects."""

    def __init__(self, stream: BinaryIO, *, keep_raw: bool = True) -> None:
        self._stream = stream
        self._keep_raw = keep_raw
        self._closed = False
        self.snaplen = 0
        self.linktype = 1
        self.nanosecond = False
        self._rec = _REC_HDR
        self._read_global_header()

    # ------------------------------------------------------------------ setup
    @classmethod
    def open(cls, path: str | os.PathLike[str], **kwargs: object) -> PcapReader:
        return cls(open(path, "rb"), **kwargs)  # noqa: SIM115 - caller owns lifecycle

    def _read_global_header(self) -> None:
        head = self._stream.read(24)
        if len(head) < 24:
            raise PcapError("file shorter than a pcap global header")
        magic_le = struct.unpack("<I", head[:4])[0]
        if magic_le == MAGIC_USEC_LE:
            endian, self.nanosecond = "<", False
        elif magic_le == MAGIC_NSEC_LE:
            endian, self.nanosecond = "<", True
        elif magic_le == MAGIC_USEC_BE:
            endian, self.nanosecond = ">", False
        elif magic_le == MAGIC_NSEC_BE:
            endian, self.nanosecond = ">", True
        else:
            raise PcapError(f"bad pcap magic 0x{magic_le:08x}")
        magic, vmaj, _vmin, _tz, _sig, snaplen, network = struct.unpack(endian + "IHHiIII", head)
        if magic not in (MAGIC_USEC_LE, MAGIC_NSEC_LE, MAGIC_USEC_BE, MAGIC_NSEC_BE):
            raise PcapError("inconsistent pcap magic")
        self.snaplen = snaplen or MAX_SNAPLEN
        self.linktype = network & 0x0FFFFFFF
        self._rec = _REC_HDR if endian == "<" else _REC_HDR_BE
        self._divisor = 1_000_000_000 if self.nanosecond else 1_000_000

    # ------------------------------------------------------------------ iteration
    def __iter__(self) -> Iterator[RawPacket]:
        rec = self._rec
        read = self._stream.read
        divisor = self._divisor
        linktype = self.linktype
        keep_raw = self._keep_raw
        while True:
            header = read(16)
            if len(header) < 16:
                break
            ts_sec, ts_frac, incl_len, orig_len = rec.unpack(header)
            if incl_len > MAX_SNAPLEN * 4:  # corrupt length guard
                raise PcapError(f"implausible record length {incl_len}")
            data = read(incl_len)
            if len(data) < incl_len:
                break  # truncated final record: stop cleanly, callers report it
            yield RawPacket(
                ts=ts_sec + ts_frac / divisor,
                data=data if keep_raw else b"",
                caplen=incl_len,
                wirelen=orig_len,
                linktype=linktype,
            )

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._stream.close()

    def __enter__(self) -> PcapReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class PcapWriter:
    """Writes little-endian microsecond pcap — the most portable dialect."""

    def __init__(self, stream: BinaryIO, *, linktype: int = 1, snaplen: int = MAX_SNAPLEN) -> None:
        self._stream = stream
        self.linktype = linktype
        self.snaplen = snaplen
        self.count = 0
        self._stream.write(_GLOBAL_HDR.pack(MAGIC_USEC_LE, 2, 4, 0, 0, min(snaplen, MAX_SNAPLEN), linktype))

    @classmethod
    def open(cls, path: str | os.PathLike[str], **kwargs: object) -> PcapWriter:
        return cls(open(path, "wb"), **kwargs)  # noqa: SIM115 - caller owns lifecycle

    def write(self, pkt: RawPacket) -> None:
        data = pkt.data[: self.snaplen]
        sec = int(pkt.ts)
        usec = int(round((pkt.ts - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec += 1
            usec -= 1_000_000
        self._stream.write(_REC_HDR.pack(sec, usec, len(data), max(len(data), pkt.wirelen)))
        self._stream.write(data)
        self.count += 1

    def close(self) -> None:
        self._stream.flush()
        self._stream.close()

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def sniff_format(head: bytes) -> str:
    """Identify a capture blob by magic: ``pcap``, ``pcapng``, ``gzip`` or ``unknown``."""
    if head[:4] == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    if len(head) >= 4:
        magic = struct.unpack("<I", head[:4])[0]
        if magic in (MAGIC_USEC_LE, MAGIC_NSEC_LE, MAGIC_USEC_BE, MAGIC_NSEC_BE):
            return "pcap"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    return "unknown"


def open_maybe_compressed(path: str | os.PathLike[str]) -> BinaryIO:
    """Open a capture, transparently decompressing gzip.

    Analysts routinely hand over ``tcpdump -z gzip`` output or zipped captures
    renamed to ``.pcap``; making that work is the difference between a tool that
    gets used and one that gets closed.
    """
    with open(path, "rb") as probe:
        head = probe.read(4)
    if head[:2] == b"\x1f\x8b":
        import gzip

        return gzip.open(path, "rb")  # type: ignore[return-value]
    return open(path, "rb")


def as_stream(source: str | os.PathLike[str] | BinaryIO) -> BinaryIO:
    if isinstance(source, (str, os.PathLike)):
        return open_maybe_compressed(source)
    if isinstance(source, io.IOBase) or hasattr(source, "read"):
        return source  # type: ignore[return-value]
    raise TypeError(f"unsupported capture source: {type(source)!r}")

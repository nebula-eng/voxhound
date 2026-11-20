"""IPv4 header parsing, fragmentation detection and reassembly."""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass

MAX_DATAGRAM = 65_535


@dataclass(slots=True)
class IPv4Header:
    ihl: int
    tos: int
    total_len: int
    ident: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    checksum: int
    src: bytes
    dst: bytes
    options: bytes

    @property
    def more_fragments(self) -> bool:
        return bool(self.flags & 0x1)

    @property
    def is_fragment(self) -> bool:
        return self.more_fragments or self.frag_offset > 0

    @property
    def header_len(self) -> int:
        return self.ihl * 4


def parse(buf: bytes | memoryview) -> IPv4Header:
    if len(buf) < 20:
        raise ValueError("short IPv4 header")
    view = memoryview(buf)
    vihl, tos, total_len, ident, frag, ttl, proto, checksum = struct.unpack_from("!BBHHHBBH", view, 0)
    version = vihl >> 4
    if version != 4:
        raise ValueError(f"IPv4 parser got version {version}")
    ihl = (vihl & 0x0F) * 4
    if ihl < 20 or len(view) < ihl:
        raise ValueError("invalid IPv4 IHL")
    return IPv4Header(
        ihl=ihl // 4,
        tos=tos,
        total_len=total_len,
        ident=ident,
        flags=(frag >> 13) & 0x7,
        frag_offset=(frag & 0x1FFF) * 8,
        ttl=ttl,
        proto=proto,
        checksum=checksum,
        src=bytes(view[12:16]),
        dst=bytes(view[16:20]),
        options=bytes(view[20:ihl]) if ihl > 20 else b"",
    )


def payload_view(buf: bytes | memoryview, hdr: IPv4Header) -> memoryview:
    """Payload bounded by ``total_len`` but never beyond the captured bytes.

    ``total_len == 0`` shows up on captures taken with TSO/GRO enabled; there we
    fall back to the captured length instead of returning nothing.
    """
    view = memoryview(buf)
    end = min(len(view), hdr.total_len) if hdr.total_len >= hdr.header_len else len(view)
    return view[hdr.header_len : end]


def format_addr(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


class IPv4Defragmenter:
    """Timeout-bounded, overlap-safe IPv4 reassembly.

    Policies chosen deliberately:

    * **first-wins** on overlapping bytes (RFC 791 leaves it implementation
      defined; first-wins matches BSD and avoids an attacker rewriting already
      delivered data),
    * hard caps on both the number of concurrent datagrams and the datagram
      size — the classic fragment-flood DoS is otherwise trivial,
    * ``MAX_AGE`` eviction so a capture can run for days.
    """

    MAX_AGE = 30.0
    MAX_DATAGRAMS = 4096

    def __init__(self) -> None:
        self._pending: dict[tuple[bytes, bytes, int, int], dict[str, object]] = {}
        self.completed = 0
        self.dropped = 0
        self.expired = 0

    def add(self, hdr: IPv4Header, payload: bytes, now: float | None = None) -> bytes | None:
        """Feed one fragment; return the full payload once complete."""
        now = now if now is not None else time.time()
        key = (hdr.src, hdr.dst, hdr.ident, hdr.proto)
        entry = self._pending.get(key)
        if entry is None:
            if len(self._pending) >= self.MAX_DATAGRAMS:
                self._evict_oldest()
                self.dropped += 1
            entry = {"chunks": {}, "total": 0, "ts": now}
            self._pending[key] = entry
        chunks: dict[int, bytes] = entry["chunks"]  # type: ignore[assignment]
        offset = hdr.frag_offset
        if offset + len(payload) > MAX_DATAGRAM:
            self._pending.pop(key, None)
            self.dropped += 1
            return None
        if offset not in chunks:
            chunks[offset] = payload
        if not hdr.more_fragments:
            entry["total"] = offset + len(payload)
        total = int(entry["total"])
        if total and _covers(chunks, total):
            assembled = bytearray(total)
            filled = bytearray(total)
            for start in sorted(chunks):
                blob = chunks[start]
                for i, byte in enumerate(blob):
                    pos = start + i
                    if pos < total and not filled[pos]:
                        assembled[pos] = byte
                        filled[pos] = 1
            self._pending.pop(key, None)
            self.completed += 1
            return bytes(assembled)
        return None

    def _evict_oldest(self) -> None:
        if not self._pending:
            return
        oldest = min(self._pending.items(), key=lambda kv: float(kv[1]["ts"]))  # type: ignore[arg-type]
        self._pending.pop(oldest[0], None)

    def expire(self, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        stale = [k for k, v in self._pending.items() if now - float(v["ts"]) > self.MAX_AGE]  # type: ignore[arg-type]
        for key in stale:
            self._pending.pop(key, None)
            self.expired += 1
        return len(stale)

    def __len__(self) -> int:
        return len(self._pending)


def _covers(chunks: dict[int, bytes], total: int) -> bool:
    """True when the byte ranges cover ``[0, total)`` without holes."""
    cursor = 0
    for start in sorted(chunks):
        if start > cursor:
            return False
        cursor = max(cursor, start + len(chunks[start]))
        if cursor >= total:
            return True
    return cursor >= total

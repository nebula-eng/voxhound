"""HTTP/2 parsing with a from-scratch HPACK decoder (RFC 7541).

HPACK is where most "we support HTTP/2" claims fall over: header blocks are
indexed against a *stateful* dynamic table and string literals are Huffman
coded. Both are implemented here — static table, dynamic table with eviction,
integer/string primitives, and the canonical Huffman code that
``scripts/gen_hpack_huffman.py`` extracts from the RFC so it can be audited.

The decoder is per-direction, as the protocol requires: client and server keep
independent compression contexts.
"""

from __future__ import annotations

import struct
from collections import deque

from ..core.model import Severity
from ._hpack_huffman import HUFFMAN_DECODE
from .base import AppSession, StreamDissector

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_TYPES = {
    0: "DATA",
    1: "HEADERS",
    2: "PRIORITY",
    3: "RST_STREAM",
    4: "SETTINGS",
    5: "PUSH_PROMISE",
    6: "PING",
    7: "GOAWAY",
    8: "WINDOW_UPDATE",
    9: "CONTINUATION",
}

FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

STATIC_TABLE: tuple[tuple[str, str], ...] = (
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
)

ENTRY_OVERHEAD = 32


class HpackError(ValueError):
    pass


def huffman_decode(data: bytes) -> bytes:
    """Decode an HPACK Huffman string, rejecting EOS and bad padding."""
    out = bytearray()
    code = 0
    bits = 0
    for byte in data:
        for shift in range(7, -1, -1):
            code = (code << 1) | ((byte >> shift) & 1)
            bits += 1
            symbol = HUFFMAN_DECODE.get((code, bits))
            if symbol is not None:
                if symbol == 256:
                    raise HpackError("EOS symbol inside Huffman string")
                out.append(symbol)
                code = 0
                bits = 0
            elif bits > 30:
                raise HpackError("Huffman code longer than 30 bits")
    if bits and code != (1 << bits) - 1:
        raise HpackError("invalid Huffman padding")
    return bytes(out)


def decode_integer(data: bytes, pos: int, prefix_bits: int) -> tuple[int, int]:
    if pos >= len(data):
        raise HpackError("integer runs past buffer")
    mask = (1 << prefix_bits) - 1
    value = data[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos
        if shift > 28:
            raise HpackError("integer too large")
    raise HpackError("truncated integer")


def decode_string(data: bytes, pos: int) -> tuple[str, int]:
    if pos >= len(data):
        raise HpackError("string runs past buffer")
    huffman = bool(data[pos] & 0x80)
    length, pos = decode_integer(data, pos, 7)
    if pos + length > len(data):
        raise HpackError("string length overruns header block")
    raw = data[pos : pos + length]
    pos += length
    if huffman:
        return huffman_decode(raw).decode("utf-8", "replace"), pos
    return raw.decode("utf-8", "replace"), pos


class HpackDecoder:
    """One compression context (one direction of one connection)."""

    def __init__(self, max_size: int = 4096) -> None:
        self.dynamic: deque[tuple[str, str]] = deque()
        self.max_size = max_size
        self.size = 0

    def lookup(self, index: int) -> tuple[str, str]:
        if index <= 0:
            raise HpackError(f"invalid table index {index}")
        if index <= len(STATIC_TABLE):
            return STATIC_TABLE[index - 1]
        position = index - len(STATIC_TABLE) - 1
        if position >= len(self.dynamic):
            raise HpackError(f"index {index} outside dynamic table ({len(self.dynamic)} entries)")
        return self.dynamic[position]

    def _evict(self) -> None:
        while self.size > self.max_size and self.dynamic:
            name, value = self.dynamic.pop()
            self.size -= len(name) + len(value) + ENTRY_OVERHEAD

    def add(self, name: str, value: str) -> None:
        entry_size = len(name) + len(value) + ENTRY_OVERHEAD
        if entry_size > self.max_size:
            self.dynamic.clear()
            self.size = 0
            return
        self.dynamic.appendleft((name, value))
        self.size += entry_size
        self._evict()

    def resize(self, new_size: int) -> None:
        self.max_size = new_size
        self._evict()

    def decode(self, block: bytes) -> list[tuple[str, str]]:
        headers: list[tuple[str, str]] = []
        pos = 0
        while pos < len(block):
            byte = block[pos]
            if byte & 0x80:  # indexed header field
                index, pos = decode_integer(block, pos, 7)
                headers.append(self.lookup(index))
            elif byte & 0x40:  # literal with incremental indexing
                index, pos = decode_integer(block, pos, 6)
                if index:
                    name = self.lookup(index)[0]
                else:
                    name, pos = decode_string(block, pos)
                value, pos = decode_string(block, pos)
                headers.append((name, value))
                self.add(name, value)
            elif byte & 0x20:  # dynamic table size update
                new_size, pos = decode_integer(block, pos, 5)
                self.resize(new_size)
            else:  # literal without indexing / never indexed
                index, pos = decode_integer(block, pos, 4)
                if index:
                    name = self.lookup(index)[0]
                else:
                    name, pos = decode_string(block, pos)
                value, pos = decode_string(block, pos)
                headers.append((name, value))
        return headers


class Http2Dissector(StreamDissector):
    name = "HTTP/2"

    def __init__(self, session: AppSession) -> None:
        super().__init__(session)
        self._buffers = [bytearray(), bytearray()]
        self._hpack = [HpackDecoder(), HpackDecoder()]
        self._blocks: dict[tuple[int, int], bytearray] = {}
        self._preface_seen = [False, False]
        self.frames = 0
        self.data_bytes = [0, 0]
        self.streams_seen: set[int] = set()

    # ------------------------------------------------------------------ input
    def feed(self, direction: int, data: bytes) -> None:
        buf = self._buffers[direction]
        buf += data
        if not self._preface_seen[direction] and buf.startswith(PREFACE[: len(buf)]):
            if len(buf) < len(PREFACE):
                return
            del buf[: len(PREFACE)]
            self._preface_seen[direction] = True
            self.s.emit("h2", "HTTP/2 connection preface", direction=direction)
        else:
            self._preface_seen[direction] = True
        while len(buf) >= 9:
            length = int.from_bytes(buf[0:3], "big")
            frame_type = buf[3]
            flags = buf[4]
            stream_id = struct.unpack_from("!I", buf[5:9])[0] & 0x7FFFFFFF
            if length > 16 << 20:
                self.s.emit("h2", f"oversized h2 frame ({length} B) — desynchronised", severity=Severity.LOW)
                buf.clear()
                return
            if len(buf) < 9 + length:
                return
            payload = bytes(buf[9 : 9 + length])
            del buf[: 9 + length]
            self.frames += 1
            self._handle_frame(direction, frame_type, flags, stream_id, payload)

    def _handle_frame(
        self, direction: int, frame_type: int, flags: int, stream_id: int, payload: bytes
    ) -> None:
        if frame_type in (1, 5):  # HEADERS / PUSH_PROMISE
            body = payload
            if flags & FLAG_PADDED and body:
                pad = body[0]
                body = body[1 : len(body) - pad] if pad < len(body) else body[1:]
            if frame_type == 1 and flags & FLAG_PRIORITY and len(body) >= 5:
                body = body[5:]
            key = (direction, stream_id)
            self._blocks.setdefault(key, bytearray()).extend(body)
            self.streams_seen.add(stream_id)
            if flags & FLAG_END_HEADERS:
                self._decode_block(direction, stream_id, bool(flags & FLAG_END_STREAM))
        elif frame_type == 9:  # CONTINUATION
            key = (direction, stream_id)
            self._blocks.setdefault(key, bytearray()).extend(payload)
            if flags & FLAG_END_HEADERS:
                self._decode_block(direction, stream_id, False)
        elif frame_type == 0:  # DATA
            self.data_bytes[direction] += len(payload)
        elif frame_type == 4:  # SETTINGS
            self.s.emit("h2", f"SETTINGS ({len(payload) // 6} params)", count=len(payload) // 6)
        elif frame_type == 6:  # PING
            self.s.emit("h2", "PING", ping=True)
        elif frame_type == 7 and len(payload) >= 8:  # GOAWAY
            last_stream, error = struct.unpack_from("!II", payload, 0)
            self.s.emit(
                "h2",
                f"GOAWAY last_stream={last_stream} error={error}",
                severity=Severity.LOW if error else Severity.INFO,
                error=error,
            )
        elif frame_type == 3 and len(payload) >= 4:  # RST_STREAM
            error = struct.unpack_from("!I", payload, 0)[0]
            self.s.emit("h2", f"RST_STREAM {stream_id} error={error}", severity=Severity.LOW, error=error)

    def _decode_block(self, direction: int, stream_id: int, end_stream: bool) -> None:
        block = self._blocks.pop((direction, stream_id), None)
        if not block:
            return
        try:
            headers = self._hpack[direction].decode(bytes(block))
        except (HpackError, struct.error) as exc:
            self.s.emit("h2", f"HPACK decode failed: {exc}", severity=Severity.LOW, stream=stream_id)
            return
        fields = dict(headers)
        method = fields.get(":method", "")
        path = fields.get(":path", "")
        authority = fields.get(":authority", "") or fields.get("host", "")
        status = fields.get(":status", "")
        if method:
            self.s.emit(
                "h2",
                f"{method} {authority}{path}",
                stream=stream_id,
                method=method,
                path=path,
                authority=authority,
                headers=len(headers),
                end_stream=end_stream,
            )
            flow = self.flow
            if (
                flow is not None
                and authority
                and authority not in flow.http_hosts
                and len(flow.http_hosts) < 32
            ):
                flow.http_hosts.append(authority)
        elif status:
            self.s.emit(
                "h2",
                f"{status} {fields.get('content-type', '')}".strip(),
                stream=stream_id,
                status=int(status) if status.isdigit() else 0,
                end_stream=end_stream,
            )
        else:
            self.s.emit("h2", f"HEADERS on stream {stream_id} ({len(headers)} fields)", stream=stream_id)

    def close(self) -> None:
        super().close()
        if self.frames:
            self.s.emit(
                "h2",
                f"HTTP/2 session closed · {self.frames} frames · {sum(self.data_bytes) / 1024:.0f} KiB data",
                frames=self.frames,
                data_bytes=sum(self.data_bytes),
                streams=len(self.streams_seen),
            )

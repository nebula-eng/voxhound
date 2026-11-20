"""TCP reassembly: the piece every serious analyser lives or dies by.

Sequence-space handling
-----------------------
Absolute offsets are computed as a *signed* 32-bit delta from the direction's
initial sequence number::

    rel = ((seq - isn + 2**31) & 0xFFFFFFFF) - 2**31

That gives ±2 GiB of unambiguous window, which is more than any real connection
will ever use, and it avoids the drift that "last seen seq + delta" accumulators
develop after a 4 GiB wraparound.

Overlap policy
--------------
**First-wins.** Bytes already delivered are never rewritten. This matches BSD
TCP behaviour and, more importantly, denies an attacker the classic trick of
retransmitting an overlapping segment to rewrite already-parsed content
(the "TCP overlap" evasion used against IDS engines).

Gaps
----
If a hole does not fill within ``gap_timeout`` seconds, the reassembler records
it and jumps forward, so one lost packet does not stall an entire conversation.
Gaps are reported to the application layer, which marks the affected artifact as
truncated instead of silently producing corrupt output.
"""

from __future__ import annotations

import bisect
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from ..core.model import FlowKey

MAX_SEGMENT_BUFFER = 8 << 20  # 8 MiB of out-of-order data per direction
PREVIEW_LIMIT = 64 << 10


def signed_delta(seq: int, base: int) -> int:
    """Shortest signed distance between two 32-bit sequence numbers."""
    return ((seq - base + 0x80000000) & 0xFFFFFFFF) - 0x80000000


@dataclass(slots=True)
class ReassemblyStats:
    segments: int = 0
    bytes: int = 0
    retransmitted: int = 0
    duplicate_bytes: int = 0
    out_of_order: int = 0
    gaps: int = 0
    gap_bytes: int = 0
    overflow: int = 0
    max_depth: int = 0


OnData = Callable[[int, int, bytes, float], None]  # (direction, absolute_offset, data, ts)


class DirectionReassembler:
    """One direction of one TCP connection."""

    __slots__ = (
        "_base",
        "_gap_timeout",
        "_last_progress",
        "_on_data",
        "direction",
        "gaps",
        "isn",
        "next_abs",
        "ooo",
        "stats",
        "syn_seen",
    )

    def __init__(self, direction: int, on_data: OnData, *, gap_timeout: float = 2.0) -> None:
        self.direction = direction
        self._on_data = on_data
        self._gap_timeout = gap_timeout
        self._base: int | None = None  # ISN (+1 when SYN carried no payload)
        self._last_progress = 0.0
        self.isn: int | None = None
        self.next_abs = 0
        self.ooo: list[tuple[int, bytes]] = []
        self.gaps: list[tuple[int, int]] = []
        self.syn_seen = False
        self.stats = ReassemblyStats()

    # ------------------------------------------------------------------ input
    def push(self, seq: int, payload: bytes, ts: float, *, syn: bool = False) -> None:
        if self._base is None:
            self.isn = seq
            self._base = seq + (1 if syn else 0)
            self._last_progress = ts
        if syn and not self.syn_seen and self.next_abs == 0:
            self.syn_seen = True
            self.isn = seq
            self._base = seq + 1
        if not payload:
            return

        self.stats.segments += 1
        data_seq = seq + (1 if syn else 0)
        rel = signed_delta(data_seq, self._base)
        if rel < 0:
            trim = -rel
            if trim >= len(payload):
                self.stats.duplicate_bytes += len(payload)
                return
            self.stats.duplicate_bytes += trim
            payload = payload[trim:]
            rel = 0

        end = rel + len(payload)
        if end <= self.next_abs:
            self.stats.duplicate_bytes += len(payload)
            self.stats.retransmitted += 1
            return

        if rel < self.next_abs:
            # Partial overlap with already delivered bytes: keep the tail only.
            overlap = self.next_abs - rel
            self.stats.duplicate_bytes += overlap
            payload = payload[overlap:]
            rel = self.next_abs

        if rel == self.next_abs:
            self._deliver(rel, payload, ts)
            self._drain(ts)
            return

        self.stats.out_of_order += 1
        self._insert(rel, payload)
        self.stats.max_depth = max(self.stats.max_depth, len(self.ooo))
        if self.gaps or self.next_abs < self.ooo[0][0]:
            self._record_gap(self.next_abs, self.ooo[0][0])

    def _insert(self, start: int, data: bytes) -> None:
        starts = [seg[0] for seg in self.ooo]
        idx = bisect.bisect_left(starts, start)
        self.ooo.insert(idx, (start, data))
        buffered = sum(len(seg[1]) for seg in self.ooo)
        while buffered > MAX_SEGMENT_BUFFER and len(self.ooo) > 1:
            _start, dropped = self.ooo.pop()
            buffered -= len(dropped)
            self.stats.overflow += len(dropped)

    def _deliver(self, offset: int, data: bytes, ts: float) -> None:
        self.next_abs = offset + len(data)
        self._last_progress = ts
        self.stats.bytes += len(data)
        self._on_data(self.direction, offset, data, ts)

    def _drain(self, ts: float) -> None:
        while self.ooo:
            start, blob = self.ooo[0]
            if start > self.next_abs:
                break
            self.ooo.pop(0)
            if start + len(blob) <= self.next_abs:
                self.stats.duplicate_bytes += len(blob)
                continue
            trim = self.next_abs - start
            self._deliver(self.next_abs, blob[trim:], ts)

    def _record_gap(self, start: int, end: int) -> None:
        if start >= end:
            return
        if self.gaps and self.gaps[-1][1] >= start:
            prev_start, prev_end = self.gaps[-1]
            self.gaps[-1] = (prev_start, max(prev_end, end))
        else:
            self.gaps.append((start, end))
        self.stats.gaps = len(self.gaps)
        self.stats.gap_bytes += end - start

    # ------------------------------------------------------------------ timers
    def maybe_skip_gap(self, now: float) -> bool:
        """Jump over a hole that has not filled within the timeout."""
        if not self.ooo or self.next_abs >= self.ooo[0][0]:
            return False
        if now - self._last_progress < self._gap_timeout:
            return False
        target = self.ooo[0][0]
        self._record_gap(self.next_abs, target)
        self.next_abs = target
        self._last_progress = now
        self._drain(now)
        return True

    def flush(self, ts: float) -> None:
        """Connection closed: skip every remaining hole, then drain."""
        guard = 0
        while self.ooo and guard < 4096:
            if self.next_abs < self.ooo[0][0]:
                self._record_gap(self.next_abs, self.ooo[0][0])
                self.next_abs = self.ooo[0][0]
            self._drain(ts)
            guard += 1


class Stream:
    """A reassembled bidirectional byte stream plus its application state."""

    __slots__ = (
        "app",
        "app_name",
        "closed",
        "first_ts",
        "flow_key",
        "gaps",
        "id",
        "last_ts",
        "preview",
        "preview_truncated",
        "reassemblers",
        "total_bytes",
        "truncated",
    )

    def __init__(self, stream_id: int, flow_key: FlowKey, first_ts: float) -> None:
        self.id = stream_id
        self.flow_key = flow_key
        self.first_ts = first_ts
        self.last_ts = first_ts
        self.closed = False
        self.truncated = False
        self.total_bytes = [0, 0]
        self.preview: list[bytearray] = [bytearray(), bytearray()]
        self.preview_truncated = False
        self.gaps: list[tuple[int, int, int]] = []  # (direction, start, end)
        self.app: object | None = None
        self.app_name = ""
        self.reassemblers = [
            DirectionReassembler(0, self._make_sink(0)),
            DirectionReassembler(1, self._make_sink(1)),
        ]

    def _make_sink(self, direction: int) -> OnData:
        def _sink(dir_: int, offset: int, data: bytes, ts: float) -> None:
            self.last_ts = max(self.last_ts, ts)
            self.total_bytes[dir_] += len(data)
            buf = self.preview[dir_]
            if len(buf) < PREVIEW_LIMIT:
                room = PREVIEW_LIMIT - len(buf)
                buf += data[:room]
                if len(data) > room:
                    self.preview_truncated = True
            app = self.app
            if app is not None:
                app.feed(dir_, data)  # type: ignore[attr-defined]

        return _sink

    # ------------------------------------------------------------------ input
    def push(self, direction: int, seq: int, payload: bytes, ts: float, *, syn: bool = False) -> None:
        self.last_ts = ts
        self.reassemblers[direction].push(seq, payload, ts, syn=syn)

    def tick(self, now: float) -> None:
        for reasm in self.reassemblers:
            reasm.maybe_skip_gap(now)

    def close(self, ts: float) -> None:
        if self.closed:
            return
        self.closed = True
        for direction, reasm in enumerate(self.reassemblers):
            reasm.flush(ts)
            for start, end in reasm.gaps:
                self.gaps.append((direction, start, end))
        app = self.app
        if app is not None:
            app.close()  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ accessors
    @property
    def byte_count(self) -> int:
        return self.total_bytes[0] + self.total_bytes[1]

    @property
    def retransmissions(self) -> int:
        return sum(r.stats.retransmitted for r in self.reassemblers)

    @property
    def out_of_order(self) -> int:
        return sum(r.stats.out_of_order for r in self.reassemblers)

    def text_preview(self, direction: int = 0, limit: int = 4096) -> str:
        raw = bytes(self.preview[direction][:limit])
        return raw.decode("utf-8", "replace")


class StreamTable:
    """Stream registry with an id counter and a bounded number of live streams."""

    def __init__(self, max_streams: int = 20_000) -> None:
        self._next_id = 1
        self.streams: dict[FlowKey, Stream] = {}
        self.closed: deque[Stream] = deque(maxlen=512)
        self.max_streams = max_streams

    def get_or_create(self, flow_key: FlowKey, ts: float) -> Stream:
        stream = self.streams.get(flow_key)
        if stream is None:
            if len(self.streams) >= self.max_streams:
                oldest_key = min(self.streams, key=lambda k: self.streams[k].last_ts)
                self.close(oldest_key, ts)
            stream = Stream(self._next_id, flow_key, ts)
            self._next_id += 1
            self.streams[flow_key] = stream
        return stream

    def get(self, flow_key: FlowKey) -> Stream | None:
        return self.streams.get(flow_key)

    def close(self, flow_key: FlowKey, ts: float) -> Stream | None:
        stream = self.streams.pop(flow_key, None)
        if stream is not None:
            stream.close(ts)
            self.closed.append(stream)
        return stream

    def close_all(self, ts: float) -> int:
        keys = list(self.streams)
        for key in keys:
            self.close(key, ts)
        return len(keys)

    def __len__(self) -> int:
        return len(self.streams)

"""IPv6 fragment reassembly.

Same policies as the IPv4 path (first-wins overlap, hard caps, 30 s expiry) —
kept as a separate class only because the key and the framing differ.
"""

from __future__ import annotations

import time

from .ipv4 import MAX_DATAGRAM, _covers


class IPv6Defragmenter:
    MAX_AGE = 30.0
    MAX_DATAGRAMS = 4096

    def __init__(self) -> None:
        self._pending: dict[tuple[bytes, bytes, int, int], dict[str, object]] = {}
        self.completed = 0
        self.dropped = 0
        self.expired = 0

    def add(
        self,
        src: bytes,
        dst: bytes,
        ident: int,
        next_header: int,
        offset: int,
        more: bool,
        payload: bytes,
        now: float | None = None,
    ) -> bytes | None:
        now = now if now is not None else time.time()
        key = (src, dst, ident, next_header)
        entry = self._pending.get(key)
        if entry is None:
            if len(self._pending) >= self.MAX_DATAGRAMS:
                oldest = min(self._pending.items(), key=lambda kv: float(kv[1]["ts"]))  # type: ignore[arg-type]
                self._pending.pop(oldest[0], None)
                self.dropped += 1
            entry = {"chunks": {}, "total": 0, "ts": now}
            self._pending[key] = entry
        chunks: dict[int, bytes] = entry["chunks"]  # type: ignore[assignment]
        if offset + len(payload) > MAX_DATAGRAM:
            self._pending.pop(key, None)
            self.dropped += 1
            return None
        chunks.setdefault(offset, payload)
        if not more:
            entry["total"] = offset + len(payload)
        total = int(entry["total"])
        if total and _covers(chunks, total):
            assembled = bytearray(total)
            filled = bytearray(total)
            for start in sorted(chunks):
                for i, byte in enumerate(chunks[start]):
                    pos = start + i
                    if pos < total and not filled[pos]:
                        assembled[pos] = byte
                        filled[pos] = 1
            self._pending.pop(key, None)
            self.completed += 1
            return bytes(assembled)
        return None

    def expire(self, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        stale = [k for k, v in self._pending.items() if now - float(v["ts"]) > self.MAX_AGE]  # type: ignore[arg-type]
        for key in stale:
            self._pending.pop(key, None)
            self.expired += 1
        return len(stale)

    def __len__(self) -> int:
        return len(self._pending)

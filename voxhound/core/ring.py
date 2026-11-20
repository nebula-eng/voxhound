"""Bounded buffers used to keep memory flat during long captures.

A forensics session can run for hours. Every unbounded list in the pipeline is a
leak waiting to happen, so the UI-facing collections are rings with a fixed
capacity, and the flow table applies a *soft* cap with LRU eviction.
"""

from __future__ import annotations

import collections
import threading
import time
from collections.abc import Iterator
from typing import Any


class RingBuffer:
    """Fixed-capacity FIFO with cheap snapshotting for the UI thread."""

    __slots__ = ("_buf", "_lock", "_capacity", "_total")

    def __init__(self, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._buf: collections.deque[Any] = collections.deque(maxlen=capacity)
        self._capacity = capacity
        self._lock = threading.Lock()
        self._total = 0

    def append(self, item: Any) -> None:
        with self._lock:
            self._buf.append(item)
            self._total += 1

    def extend(self, items: list[Any]) -> None:
        with self._lock:
            self._buf.extend(items)
            self._total += len(items)

    def snapshot(self) -> list[Any]:
        with self._lock:
            return list(self._buf)

    def latest(self, n: int = 1) -> list[Any]:
        with self._lock:
            if n >= len(self._buf):
                return list(self._buf)
            return list(self._buf)[-n:]

    def clear(self) -> None:
        with self._lock:
            self._buf.clear()

    @property
    def total_seen(self) -> int:
        return self._total

    def __len__(self) -> int:
        return len(self._buf)

    def __iter__(self) -> Iterator[Any]:
        return iter(self.snapshot())


class RateMeter:
    """Sliding-window rate in events/second and bytes/second.

    One bucket per second, default 10 s window: cheap to update from the capture
    thread (no locks in the hot path beyond one deque append) and smooth enough
    for a 10 Hz UI refresh.
    """

    __slots__ = ("_window", "_buckets", "_lock")

    def __init__(self, window: int = 10) -> None:
        self._window = window
        self._buckets: collections.deque[tuple[int, int, int]] = collections.deque(maxlen=window)
        self._lock = threading.Lock()

    def add(self, count: int = 1, nbytes: int = 0, ts: float | None = None) -> None:
        sec = int(ts if ts is not None else time.time())
        with self._lock:
            if self._buckets and self._buckets[-1][0] == sec:
                s, c, b = self._buckets[-1]
                self._buckets[-1] = (s, c + count, b + nbytes)
            else:
                self._buckets.append((sec, count, nbytes))

    def rates(self, now: float | None = None) -> tuple[float, float]:
        """Return ``(events_per_second, bytes_per_second)`` over the window."""
        now_sec = int(now if now is not None else time.time())
        with self._lock:
            buckets = list(self._buckets)
        if not buckets:
            return 0.0, 0.0
        horizon = now_sec - self._window + 1
        live = [(c, b) for s, c, b in buckets if s >= horizon]
        if not live:
            return 0.0, 0.0
        span = max(1, min(self._window, now_sec - min(s for s, _, _ in buckets) + 1))
        return sum(c for c, _ in live) / span, sum(b for _, b in live) / span


class TimeSeries:
    """Per-second counters, kept for the dashboard sparklines and the report."""

    __slots__ = ("_series", "_keys", "_capacity", "_lock")

    def __init__(self, keys: tuple[str, ...] = ("packets", "bytes"), capacity: int = 900) -> None:
        self._keys = keys
        self._series: collections.deque[tuple[int, dict[str, float]]] = collections.deque(maxlen=capacity)
        self._lock = threading.Lock()

    def add(self, ts: float, **values: float) -> None:
        sec = int(ts)
        with self._lock:
            if self._series and self._series[-1][0] == sec:
                s, row = self._series[-1]
                for k, v in values.items():
                    row[k] = row.get(k, 0.0) + v
                self._series[-1] = (s, row)
            else:
                self._series.append((sec, dict(values)))

    def rows(self) -> list[tuple[int, dict[str, float]]]:
        with self._lock:
            return [(s, dict(r)) for s, r in self._series]

    def series(self, key: str) -> list[float]:
        with self._lock:
            return [float(r.get(key, 0.0)) for _, r in self._series]

    def clear(self) -> None:
        with self._lock:
            self._series.clear()

"""A tiny thread-safe publish/subscribe bus.

The capture pipeline runs on its own thread(s); the Qt front-end must never be
touched from those threads. The bus is the seam: engine emits, the UI adapter
turns events into queued Qt signals, everything stays decoupled and testable.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

log = logging.getLogger(__name__)

Handler = Callable[[Any], None]


class EventBus:
    """Fan-out with wildcard support and per-handler fault isolation."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = {}
        self._lock = threading.RLock()

    def subscribe(self, kind: str, handler: Handler) -> Callable[[], None]:
        """Subscribe to ``kind`` (or ``"*"``). Returns an unsubscribe callable."""
        with self._lock:
            self._handlers.setdefault(kind, []).append(handler)

        def _off() -> None:
            self.unsubscribe(kind, handler)

        return _off

    def unsubscribe(self, kind: str, handler: Handler) -> None:
        with self._lock:
            bucket = self._handlers.get(kind)
            if bucket and handler in bucket:
                bucket.remove(handler)

    def publish(self, kind: str, payload: Any = None) -> None:
        with self._lock:
            targets = list(self._handlers.get(kind, ()))
            if kind != "*":
                targets.extend(self._handlers.get("*", ()))
        for handler in targets:
            try:
                handler(payload)
            except Exception:  # a broken subscriber must not kill the capture thread
                log.exception("event handler failed for kind=%s", kind)

    def clear(self) -> None:
        with self._lock:
            self._handlers.clear()

    def handler_count(self, kind: str | None = None) -> int:
        with self._lock:
            if kind is None:
                return sum(len(v) for v in self._handlers.values())
            return len(self._handlers.get(kind, ()))

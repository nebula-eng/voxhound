"""Application-layer dissector contract.

A dissector sees one direction of a byte stream at a time, in order, with gaps
already resolved by the transport layer. It may:

* publish events (``session.emit``) — these become the activity feed, rule input
  and report content,
* carve artifacts (``session.artifact``) — audio, images, documents,
* annotate the flow (``session.tag`` / ``session.note``) — surfaced in the UI.

Dissectors are intentionally stateful and single-connection: no globals, no
threading assumptions. The flow manager owns their lifetime and calls ``close``
exactly once.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from ..core.model import AppEvent, Artifact, Severity
from ..core.util import safe_filename, sha256_hex


class Dissector(Protocol):
    """Anything that can consume stream or datagram bytes."""

    name: str

    def feed(self, direction: int, data: bytes) -> None: ...

    def close(self) -> None: ...


class AppSession:
    """Per-connection context handed to a dissector.

    Keeping this object tiny matters: one exists per stream, and a busy capture
    can hold tens of thousands of streams.
    """

    __slots__ = ("app_name", "flow", "kind", "meta", "_artifact_sink", "_event_sink", "stream", "ts")

    def __init__(
        self,
        flow: Any,
        stream: Any,
        *,
        event_sink: Callable[[AppEvent], None],
        artifact_sink: Callable[[Artifact], None],
        ts: float = 0.0,
        kind: str = "stream",
    ) -> None:
        self.flow = flow
        self.stream = stream
        self.ts = ts
        self.kind = kind
        self.app_name = ""
        self.meta: dict[str, Any] = {}
        self._event_sink = event_sink
        self._artifact_sink = artifact_sink

    # ------------------------------------------------------------------ events
    def emit(self, kind: str, title: str, *, severity: int = Severity.INFO, **detail: Any) -> None:
        self._event_sink(
            AppEvent(
                ts=self.ts,
                kind=kind,
                title=title,
                flow_key=getattr(self.flow, "key", None),
                severity=int(severity),
                detail=detail,
            )
        )

    # ------------------------------------------------------------------ artifacts
    def artifact(
        self, kind: str, name: str, data: bytes, *, source: str = "", **meta: Any
    ) -> Artifact | None:
        """Carve a payload. Duplicate bytes (same hash) are dropped by the engine."""
        if not data:
            return None
        art = Artifact(
            ts=self.ts,
            kind=kind,
            name=safe_filename(name, fallback=kind.replace("/", "-")),
            data=data,
            source=source or self.app_name or "stream",
            flow_key=getattr(self.flow, "key", None),
            stream_id=getattr(self.stream, "id", 0),
            meta=dict(meta),
            sha256=sha256_hex(data),
        )
        self._artifact_sink(art)
        return art

    # ------------------------------------------------------------------ annotations
    def tag(self, tag: str) -> None:
        flow = self.flow
        if flow is not None and hasattr(flow, "tags") and tag not in flow.tags:
            flow.tags.append(tag)

    def note(self, key: str, value: Any) -> None:
        flow = self.flow
        if flow is not None and hasattr(flow, "notes"):
            flow.notes[key] = value


class StreamDissector:
    """Convenience base class: keeps the session and a sane default ``close``."""

    name = "stream"

    def __init__(self, session: AppSession) -> None:
        self.s = session
        self.closed = False

    def feed(self, direction: int, data: bytes) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def close(self) -> None:
        self.closed = True

    # -- helpers ---------------------------------------------------------
    @property
    def flow(self) -> Any:
        return self.s.flow

    def summary(self) -> str:
        return self.name

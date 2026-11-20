"""Threading bridge between the engine and the Qt event loop.

The engine is single-threaded by design; the GUI must never block. So:

* :class:`EngineWorker` lives in a ``QThread`` and calls ``engine.run()``,
* engine callbacks buffer their items and emit **batched** Qt signals,
* the GUI thread only ever sees ``list[tuple]`` / dataclass snapshots, never a
  live engine object — no shared mutable state, no locks, no surprises.

Stopping is cooperative via ``threading.Event``; the worker closes the capture
source on the way out so a stop does not leak a pcap handle.
"""

from __future__ import annotations

import time
from threading import Event
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal, Slot

from ..core.model import Alert, AppEvent, Artifact, Packet
from ..engine import Engine, Report
from ..export.report import write_html

PACKET_FLUSH = 48
FLOW_EVERY_S = 1.2


class EngineWorker(QObject):
    packets = Signal(list)
    events = Signal(list)
    alerts = Signal(list)
    artifacts = Signal(list)
    flows = Signal(list)
    stats = Signal(dict)
    log = Signal(str)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        spec: str,
        *,
        filter_expr: str = "",
        duration: float | None = None,
        options: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self.spec = spec
        self.filter_expr = filter_expr
        self.duration = duration
        self.options = options or {}
        self._stop = Event()
        self._packet_buf: list[tuple[Any, ...]] = []
        self._event_buf: list[dict[str, Any]] = []
        self._alert_buf: list[dict[str, Any]] = []
        self._artifact_buf: list[dict[str, Any]] = []
        self._artifact_objects: list[Artifact] = []
        self._last_flush = 0.0
        self._last_flows = 0.0
        self._first_ts: float | None = None
        self.engine: Engine | None = None
        self._max_artifact_bytes = 512 << 20

    # ------------------------------------------------------------------ slots
    @Slot()
    def run(self) -> None:
        try:
            live = self.spec.startswith("iface:")
            engine = Engine(
                filter_expr="" if live else self.filter_expr,
                verify_checksums=bool(self.options.get("verify_checksums")),
                enable_rules=not self.options.get("no_rules", False),
                enable_anomaly=not self.options.get("no_heuristics", False),
                keep_packets=0,
            )
            if live:
                # kernel filter already applied; keep it for the report header
                engine.filter_expr = self.filter_expr
            self.engine = engine
            rules_path = self.options.get("rules")
            if rules_path:
                engine.add_rules_from(rules_path)
            engine.on_packet = self._on_packet
            engine.on_event = self._on_event
            engine.on_alert = self._on_alert
            engine.on_artifact = self._on_artifact
            engine.on_progress = self._on_progress
            from ..capture.source import open_source

            source = open_source(self.spec, **self.options.get("source_kwargs", {}))
            self.log.emit(f"正在从 {source.description} 抓包")
            report = engine.run(source, duration=self.duration, stop_event=self._stop, progress_interval=0.4)
            self._flush_packets(force=True)
            self._flush_events(force=True)
            self._flush_alerts(force=True)
            self._flush_artifacts(force=True)
            self.finished.emit(report)
        except Exception as exc:  # noqa: BLE001 - surface, never crash the app
            self.failed.emit(f"{type(exc).__name__}: {exc}")

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------ callbacks
    def _on_packet(self, pkt: Packet, raw: bytes) -> None:
        if self._first_ts is None:
            self._first_ts = pkt.ts
        rel = pkt.ts - self._first_ts
        self._packet_buf.append(
            (
                pkt.number,
                f"{rel:.3f}",
                pkt.src or pkt.eth_src,
                pkt.dst or pkt.eth_dst,
                pkt.proto_name,
                pkt.wirelen,
                pkt.info or pkt.summary(),
                pkt.app or "",
                raw[:65535],
            )
        )
        now = time.monotonic()
        if len(self._packet_buf) >= PACKET_FLUSH or now - self._last_flush > 0.12:
            self._flush_packets()

    def _flush_packets(self, *, force: bool = False) -> None:
        if not self._packet_buf:
            return
        if not force and len(self._packet_buf) < 8:
            return
        self.packets.emit(self._packet_buf)
        self._packet_buf = []
        self._last_flush = time.monotonic()

    def _on_event(self, event: AppEvent) -> None:
        self._event_buf.append(
            {
                "ts": event.ts,
                "kind": event.kind,
                "title": event.title,
                "severity": int(event.severity),
                "flow": _endpoints(event.flow_key),
                "detail": event.detail,
            }
        )
        if len(self._event_buf) >= 24:
            self._flush_events()

    def _flush_events(self, *, force: bool = False) -> None:
        if not self._event_buf:
            return
        if not force and len(self._event_buf) < 4:
            return
        self.events.emit(self._event_buf)
        self._event_buf = []

    def _on_alert(self, alert: Alert) -> None:
        from datetime import datetime

        self._alert_buf.append(
            {
                "ts": alert.ts,
                "time": datetime.fromtimestamp(alert.ts).strftime("%H:%M:%S") if alert.ts else "--:--:--",
                "rule": alert.rule_id,
                "title": alert.title,
                "severity": int(alert.severity),
                "description": alert.description,
                "flow": _endpoints(alert.flow_key),
                "evidence": alert.evidence,
            }
        )
        if len(self._alert_buf) >= 6:
            self._flush_alerts()

    def _flush_alerts(self, *, force: bool = False) -> None:
        if not self._alert_buf:
            return
        if not force and len(self._alert_buf) < 2:
            return
        self.alerts.emit(self._alert_buf)
        self._alert_buf = []

    def _on_artifact(self, artifact: Artifact) -> None:
        total = sum(len(a.data) for a in self._artifact_objects)
        if total + len(artifact.data) > self._max_artifact_bytes:
            return
        self._artifact_objects.append(artifact)
        self._artifact_buf.append(
            {
                "ts": artifact.ts,
                "kind": artifact.kind,
                "name": artifact.name,
                "size": artifact.size,
                "source": artifact.source,
                "sha256": artifact.sha256,
                "meta": artifact.meta,
                "_object": artifact,
            }
        )
        self._flush_artifacts()

    def _flush_artifacts(self, *, force: bool = False) -> None:
        if not self._artifact_buf:
            return
        if not force and len(self._artifact_buf) < 2:
            return
        self.artifacts.emit(self._artifact_buf)
        self._artifact_buf = []

    def _on_progress(self, snapshot: dict[str, Any]) -> None:
        self._flush_packets()
        self._flush_events()
        self._flush_alerts()
        now = time.monotonic()
        if self.engine is not None and now - self._last_flows > FLOW_EVERY_S:
            self._last_flows = now
            rows = []
            flows = sorted(self.engine.flows.iter_flows(), key=lambda f: f.payload_bytes, reverse=True)
            for flow in flows[:1500]:
                row = flow.row()
                row["client"] = f"{flow.src}:{flow.sport}"
                row["server"] = f"{flow.dst}:{flow.dport}"
                rows.append(row)
            self.flows.emit(rows)
        snapshot = dict(snapshot)
        if self.engine is not None:
            elapsed = max(0.001, time.time() - self.engine.stats.started_at)
            if float(snapshot.get("pps", 0)) <= 0.5 and self.engine.stats.packets:
                snapshot["pps"] = self.engine.stats.packets / elapsed
                snapshot["bps"] = self.engine.stats.wire_bytes / elapsed
            snapshot["alerts_high"] = sum(1 for alert in self.engine.alerts if int(alert.severity) >= 3)
            snapshot["series"] = [row.get("packets", 0.0) for _, row in self.engine.series.rows()][-180:]
            snapshot["apps"] = dict(self.engine.app_counts_for_ui())
            snapshot["protocols"] = dict(self.engine.protocol_counts)
            snapshot["talkers"] = self.engine.top_talkers_for_ui(8)
        self.stats.emit(snapshot)


def _endpoints(key: Any) -> str:
    if not key or len(key) < 5:
        return ""
    _proto, addr_a, port_a, addr_b, port_b = key[:5]
    return f"{_addr(addr_a)}:{port_a} ↔ {_addr(addr_b)}:{port_b}"


def _addr(raw: Any) -> str:
    if isinstance(raw, bytes):
        if len(raw) == 4:
            return ".".join(str(b) for b in raw)
        if len(raw) == 16:
            return ":".join(f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2))
    return str(raw)


class CaptureController(QObject):
    """Owns the worker thread and exposes a tiny start/stop surface."""

    packets = Signal(list)
    events = Signal(list)
    alerts = Signal(list)
    artifacts = Signal(list)
    flows = Signal(list)
    stats = Signal(dict)
    log = Signal(str)
    finished = Signal(object)
    failed = Signal(str)
    running_changed = Signal(bool)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: EngineWorker | None = None
        self._last_report: Report | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.isRunning()

    @property
    def report(self) -> Report | None:
        return self._last_report

    def start(
        self,
        spec: str,
        *,
        filter_expr: str = "",
        duration: float | None = None,
        options: dict[str, Any] | None = None,
    ) -> None:
        if self.running:
            return
        thread = QThread()
        worker = EngineWorker(spec, filter_expr=filter_expr, duration=duration, options=options)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.packets.connect(self.packets)
        worker.events.connect(self.events)
        worker.alerts.connect(self.alerts)
        worker.artifacts.connect(self.artifacts)
        worker.flows.connect(self.flows)
        worker.stats.connect(self.stats)
        worker.log.connect(self.log)
        worker.failed.connect(self.failed)
        worker.finished.connect(self._on_finished)
        worker.finished.connect(thread.quit)
        thread.finished.connect(self._on_thread_finished)
        self._thread = thread
        self._worker = worker
        self.running_changed.emit(True)
        thread.start()

    def _on_finished(self, report: Report) -> None:
        self._last_report = report
        self.finished.emit(report)

    def _on_thread_finished(self) -> None:
        self._worker = None
        self._thread = None
        self.running_changed.emit(False)

    def stop(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self.log.emit("正在停止抓包……")

    def save_report(self, path: str) -> str:
        if self._last_report is None:
            raise RuntimeError("nothing to save yet")
        return str(write_html(self._last_report, path))

    def wait(self, timeout_ms: int = 5000) -> bool:
        if self._thread is None:
            return True
        return self._thread.wait(timeout_ms)

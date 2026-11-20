"""The engine: one object that turns bytes into findings.

    source ──► Decoder ──► filter ──► FlowManager ──► dissectors
                                            │
                                            ├─► events  ──► rule engine ──► alerts
                                            ├─► artifacts (bounded)
                                            └─► behavioural heuristics ──► alerts

Everything is synchronous and single-threaded here; concurrency is the caller's
problem (the GUI runs this on a worker thread and marshals callbacks through Qt
signals). That keeps the engine trivially testable and free of locks.
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Any

from . import __version__
from .capture.filter import Filter, compile_filter
from .capture.source import CaptureSource, FileSource, open_source
from .core.bus import EventBus
from .core.model import Alert, AppEvent, Artifact, CaptureStats, Packet, RawPacket
from .core.ring import RateMeter, RingBuffer, TimeSeries
from .decode import Decoder
from .flows.anomaly import AnomalyAnalyzer
from .flows.table import FlowManager
from .rules.engine import RuleEngine

log = logging.getLogger(__name__)

PacketCallback = Callable[[Packet, bytes], None]
EventCallback = Callable[[AppEvent], None]
AlertCallback = Callable[[Alert], None]
ArtifactCallback = Callable[[Artifact], None]
ProgressCallback = Callable[[dict[str, Any]], None]


@dataclass(slots=True)
class Report:
    """Immutable-ish snapshot produced at the end of a run."""

    version: str = __version__
    started_at: float = 0.0
    finished_at: float = 0.0
    stats: dict[str, Any] = field(default_factory=dict)
    flows: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    protocols: dict[str, int] = field(default_factory=dict)
    apps: dict[str, int] = field(default_factory=dict)
    top_talkers: list[dict[str, Any]] = field(default_factory=list)
    series: list[tuple[int, dict[str, float]]] = field(default_factory=list)
    hosts: list[dict[str, Any]] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.finished_at - self.started_at)

    def summary(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "duration_s": round(self.duration, 2),
            "packets": self.stats.get("packets", 0),
            "bytes": self.stats.get("wire_bytes", 0),
            "flows": len(self.flows),
            "events": len(self.events),
            "alerts": len(self.alerts),
            # ``Report`` carries plain dicts (they are serialised straight to JSON),
            # not ``Alert`` objects — attribute access here crashed ``--json``.
            "alerts_high": sum(1 for a in self.alerts if int(a.get("severity", 0)) >= 3),
            "artifacts": len(self.artifacts),
            "apps": self.apps,
        }


class Engine:
    """Configurable analysis pipeline."""

    def __init__(
        self,
        *,
        filter_expr: str = "",
        verify_checksums: bool = False,
        rules: RuleEngine | None = None,
        max_flows: int = 120_000,
        event_capacity: int = 5_000,
        alert_capacity: int = 5_000,
        artifact_budget: int = 256 << 20,
        keep_packets: int = 0,
        enable_rules: bool = True,
        enable_anomaly: bool = True,
        carve_streams: bool = True,
        bus: EventBus | None = None,
    ) -> None:
        self.bus = bus or EventBus()
        self.stats = CaptureStats()
        self.filter: Filter = compile_filter(filter_expr)
        self.filter_expr = filter_expr
        self.decoder = Decoder(verify_checksums=verify_checksums)
        self.rules = (
            rules if rules is not None else (RuleEngine.load_builtin() if enable_rules else RuleEngine())
        )
        self.enable_rules = enable_rules
        self.enable_anomaly = enable_anomaly

        self.flows = FlowManager(
            on_event=self._on_event,
            on_artifact=self._on_artifact,
            stats=self.stats,
            max_flows=max_flows,
            carve_streams=carve_streams,
        )
        self.anomaly = AnomalyAnalyzer(self._on_alert)

        self.events: RingBuffer = RingBuffer(event_capacity)
        self.alerts: list[Alert] = []
        self.alert_capacity = alert_capacity
        self.artifacts: list[Artifact] = []
        self.artifact_budget = artifact_budget
        self.artifact_bytes = 0
        self._artifact_hashes: set[str] = set()
        self._artifact_dropped = 0

        self.packets = RingBuffer(keep_packets) if keep_packets else None
        self.series = TimeSeries()
        self.rate = RateMeter(window=10)
        self.protocol_counts: Counter[str] = Counter()
        self.event_kinds: Counter[str] = Counter()
        self.filtered_out = 0

        # callbacks (the GUI overrides these)
        self.on_packet: PacketCallback | None = None
        self.on_event: EventCallback | None = None
        self.on_alert: AlertCallback | None = None
        self.on_artifact: ArtifactCallback | None = None
        self.on_progress: ProgressCallback | None = None

    # ------------------------------------------------------------------ convenience
    def analyze_file(self, path: str | Path, **kwargs: Any) -> Report:
        source = FileSource(str(path))
        return self.run(source, **kwargs)

    # ------------------------------------------------------------------ packet path
    def process(self, raw: RawPacket) -> Packet | None:
        number = self.stats.packets + 1
        pkt = self.decoder.decode(raw, number)
        if pkt is None:
            return None
        self.stats.packets = number
        self.stats.bytes += raw.caplen
        self.stats.wire_bytes += max(raw.wirelen, raw.caplen)
        if not self.stats.first_ts:
            self.stats.first_ts = raw.ts
        self.stats.last_ts = max(self.stats.last_ts, raw.ts)
        if pkt.malformed:
            self.stats.malformed += 1

        if not self.filter(pkt):
            self.filtered_out += 1
            return pkt

        flow = self.flows.process(pkt)
        if flow is not None:
            self.protocol_counts[flow.proto_name] += 1
        if self.enable_anomaly:
            self.anomaly.observe_packet(pkt)

        self.rate.add(1, raw.caplen, raw.ts)
        self.series.add(raw.ts, packets=1, bytes=raw.caplen)
        if self.packets is not None:
            self.packets.append((pkt, raw.data))
        if self.on_packet is not None:
            self.on_packet(pkt, raw.data)
        return pkt

    # ------------------------------------------------------------------ events
    def _on_event(self, event: AppEvent) -> None:
        self.events.append(event)
        self.event_kinds[event.kind or "other"] += 1
        flow = self.flows.find(event.flow_key) if event.flow_key else None
        if self.enable_rules:
            for alert in self.rules.evaluate_event(event, flow):
                self._on_alert(alert)
        if self.enable_anomaly:
            self.anomaly.observe_event(event, flow)
        if self.on_event is not None:
            self.on_event(event)
        self.bus.publish("event", event)

    def _on_alert(self, alert: Alert) -> None:
        if len(self.alerts) >= self.alert_capacity:
            self.alerts.pop(0)
        self.alerts.append(alert)
        if self.on_alert is not None:
            self.on_alert(alert)
        self.bus.publish("alert", alert)

    def _on_artifact(self, artifact: Artifact) -> None:
        if not artifact.data:
            return
        if artifact.sha256 and artifact.sha256 in self._artifact_hashes:
            return
        if self.artifact_bytes + len(artifact.data) > self.artifact_budget:
            self._artifact_dropped += 1
            return
        self.artifact_bytes += len(artifact.data)
        if artifact.sha256:
            self._artifact_hashes.add(artifact.sha256)
            if len(self._artifact_hashes) > 50_000:
                self._artifact_hashes.clear()
        self.artifacts.append(artifact)
        if self.on_artifact is not None:
            self.on_artifact(artifact)
        self.bus.publish("artifact", artifact)

    # ------------------------------------------------------------------ running
    def run(
        self,
        source: CaptureSource,
        *,
        duration: float | None = None,
        stop_event: Event | None = None,
        progress_interval: float = 0.5,
        batch_size: int = 1024,
    ) -> Report:
        source.open()
        self.stats.started_at = time.time()
        self.stats.capture_filter = self.filter_expr
        started = self.stats.started_at
        last_tick = 0.0
        last_progress = 0.0
        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    break
                # The deadline must be checked before reading: a busy link always
                # returns a batch, so checking it only on an empty read lets a
                # 6-second capture run until the traffic pauses.
                if duration is not None and time.time() - started >= duration:
                    break
                batch = source.read_batch(batch_size)
                if batch:
                    for raw in batch:
                        self.process(raw)
                else:
                    if source.eof:
                        break
                    time.sleep(0.004)
                now = self.stats.last_ts or time.time()
                if now - last_tick >= 1.0:
                    last_tick = now
                    self._tick(now)
                clock = time.time()
                if progress_interval and clock - last_progress >= progress_interval:
                    last_progress = clock
                    self._emit_progress(source)
        finally:
            try:
                source.close()
            except Exception:  # noqa: BLE001
                log.debug("source close failed", exc_info=True)
            recv, dropped = source.driver_stats()
            if dropped:
                self.stats.if_dropped = dropped
            if recv:
                self.stats.dropped = max(0, recv - self.stats.packets)
        return self.finalize()

    def run_spec(self, spec: str, **kwargs: Any) -> Report:
        source_kwargs: dict[str, Any] = {}
        for key in ("replay", "speed", "duration", "seed"):
            if key in kwargs:
                source_kwargs[key] = kwargs.pop(key)
        source = open_source(spec, **source_kwargs)
        return self.run(source, **kwargs)

    def _tick(self, now: float) -> None:
        self.flows.expire(now)
        self.decoder.expire_fragments(now)
        if self.enable_anomaly:
            self.anomaly.tick(now)

    def _emit_progress(self, source: CaptureSource) -> None:
        if self.on_progress is None:
            return
        pps, bps = self.rate.rates()
        self.on_progress(
            {
                "packets": self.stats.packets,
                "bytes": self.stats.wire_bytes,
                "flows": len(self.flows),
                "events": len(self.events),
                "alerts": len(self.alerts),
                # Live counters come from ``Alert`` objects; the finished report
                # carries dicts, so the two must not share an accessor.
                "alerts_high": sum(1 for a in self.alerts if int(a.severity) >= 3),
                "artifacts": len(self.artifacts),
                "pps": pps,
                "bps": bps,
                "elapsed": time.time() - self.stats.started_at,
                "source": source.description,
                "eof": source.eof,
            }
        )

    # ------------------------------------------------------------------ finishing
    def finalize(self) -> Report:
        last_ts = self.stats.last_ts or time.time()
        self.flows.close_all(last_ts)
        if self.enable_anomaly:
            for flow in list(self.flows.flows.values()):
                self.anomaly.observe_flow(flow)
        if self.enable_rules:
            for flow in list(self.flows.flows.values()):
                for alert in self.rules.evaluate_flow(flow):
                    self._on_alert(alert)
        self.stats.last_ts = last_ts
        report = self.build_report()
        self.bus.publish("finished", report)
        return report

    def build_report(self) -> Report:
        flows = [flow.row() for flow in self.flows.iter_flows()]
        flows.sort(key=lambda row: row["bytes"], reverse=True)
        events = [
            {
                "ts": ev.ts,
                "kind": ev.kind,
                "title": ev.title,
                "severity": int(ev.severity),
                "flow": _flow_label(ev.flow_key),
                "detail": {k: _jsonable(v) for k, v in ev.detail.items()},
            }
            for ev in self.events.snapshot()
        ]
        alerts = [
            {
                "ts": a.ts,
                "rule": a.rule_id,
                "title": a.title,
                "severity": int(a.severity),
                "severity_label": a.severity_label,
                "description": a.description,
                "flow": _flow_label(a.flow_key),
                "evidence": {k: _jsonable(v) for k, v in a.evidence.items()},
            }
            for a in self.alerts
        ]
        artifacts = [
            {
                "ts": art.ts,
                "kind": art.kind,
                "name": art.name,
                "size": art.size,
                "sha256": art.sha256,
                "source": art.source,
                "flow": _flow_label(art.flow_key),
                "meta": {k: _jsonable(v) for k, v in art.meta.items()},
            }
            for art in self.artifacts
        ]
        return Report(
            version=__version__,
            started_at=self.stats.started_at or (self.stats.first_ts or time.time()),
            finished_at=time.time(),
            stats=self.stats.as_dict(),
            flows=flows,
            events=events,
            alerts=alerts,
            artifacts=artifacts,
            protocols=dict(self.protocol_counts.most_common()),
            apps=dict(Counter(f.app for f in self.flows.iter_flows() if f.app).most_common(32)),
            top_talkers=self._top_talkers(),
            series=self.series.rows(),
            hosts=self._hosts(),
        )

    def _top_talkers(self, limit: int = 12) -> list[dict[str, Any]]:
        per_host: dict[str, dict[str, Any]] = {}
        for flow in self.flows.iter_flows():
            for host, sent in ((flow.src, flow.bytes_a), (flow.dst, flow.bytes_b)):
                entry = per_host.setdefault(host, {"host": host, "bytes": 0, "packets": 0, "flows": 0})
                entry["bytes"] += sent
                entry["flows"] += 1
        for pkt_host, count in self.protocol_counts.items():
            del pkt_host, count
        rows = sorted(per_host.values(), key=lambda row: row["bytes"], reverse=True)
        return rows[:limit]

    def _hosts(self) -> list[dict[str, Any]]:
        """Host inventory: names learned from DNS/SNI/HTTP, plus TX/RX volumes."""
        inventory: dict[str, dict[str, Any]] = {}
        for flow in self.flows.iter_flows():
            for host, sent, received in (
                (flow.src, flow.bytes_a, flow.bytes_b),
                (flow.dst, flow.bytes_b, flow.bytes_a),
            ):
                entry = inventory.setdefault(
                    host,
                    {"host": host, "names": [], "tx": 0, "rx": 0, "flows": 0, "apps": []},
                )
                entry["tx"] += sent
                entry["rx"] += received
                entry["flows"] += 1
                for name in ([flow.sni] if flow.sni else []) + flow.dns_names[:2] + flow.http_hosts[:2]:
                    if name and name not in entry["names"] and len(entry["names"]) < 8:
                        entry["names"].append(name)
                if flow.app and flow.app not in entry["apps"]:
                    entry["apps"].append(flow.app)
        for name in list(inventory):
            inventory[name]["names"] = inventory[name]["names"][:8]
            inventory[name]["apps"] = inventory[name]["apps"][:6]
        return sorted(inventory.values(), key=lambda row: row["tx"] + row["rx"], reverse=True)

    # ------------------------------------------------------------------ introspection
    def snapshot(self) -> dict[str, Any]:
        """Everything the dashboard needs, cheap to call at 10 Hz."""
        pps, bps = self.rate.rates()
        return {
            "packets": self.stats.packets,
            "bytes": self.stats.wire_bytes,
            "flows": len(self.flows),
            "open_flows": sum(1 for f in self.flows.iter_flows() if not f.closed),
            "streams": len(self.flows.streams),
            "events": len(self.events),
            "alerts": len(self.alerts),
            # ``Report`` carries plain dicts (they are serialised straight to JSON),
            # not ``Alert`` objects — attribute access here crashed ``--json``.
            "alerts_high": sum(1 for a in self.alerts if int(a.severity) >= 3),
            "artifacts": len(self.artifacts),
            "filtered": self.filtered_out,
            "malformed": self.stats.malformed,
            "dropped": self.stats.dropped,
            "pps": pps,
            "bps": bps,
            "series": self.series.rows(),
            "protocols": dict(self.protocol_counts.most_common(10)),
            "event_kinds": dict(self.event_kinds.most_common(4)),
            "artifact_kinds": dict(
                Counter(str(item.kind).split("/", 1)[0] for item in self.artifacts).most_common(4)
            ),
            "apps": dict(self.app_counts.most_common(10)),
            "decoder": dict(self.decoder.stats),
        }

    def app_counts_for_ui(self, limit: int = 8) -> dict[str, int]:
        """Flows attributed to each dissector — what the dashboard donut shows."""
        return dict(Counter(f.app for f in self.flows.iter_flows() if f.app).most_common(limit))

    def top_talkers_for_ui(self, limit: int = 8) -> list[tuple[str, int]]:
        rows = self._top_talkers(limit)
        return [(str(row["host"]), int(row["bytes"])) for row in rows]

    def set_filter(self, expression: str) -> None:
        self.filter = compile_filter(expression)
        self.filter_expr = expression
        self.stats.capture_filter = expression

    # ------------------------------------------------------------------ rules
    def add_rules_from(self, path: str | Path) -> int:
        target = Path(path)
        if target.is_dir():
            return self.rules.add_from_dir(target)
        return self.rules.add_from_file(target)


def _flow_label(key: tuple[Any, ...] | None) -> str:
    if not key or len(key) < 5:
        return ""
    proto, addr_a, port_a, addr_b, port_b = key[:5]
    return f"{_addr(addr_a)}:{port_a} ↔ {_addr(addr_b)}:{port_b}"


def _addr(raw: object) -> str:
    if isinstance(raw, bytes):
        if len(raw) == 4:
            return ".".join(str(b) for b in raw)
        if len(raw) == 16:
            return ":".join(f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2))
        return raw.hex()
    return str(raw)


def _jsonable(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return value.hex()[:512]
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in list(value)[:32]]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in list(value.items())[:32]}
    return str(value)


def analyze(
    spec: str | None = None,
    *,
    filter_expr: str = "",
    rules_path: str | Path | None = None,
    duration: float | None = None,
    progress: ProgressCallback | None = None,
) -> Report:
    """Convenience one-liner used by the CLI and by scripts."""
    engine = Engine(filter_expr=filter_expr, keep_packets=0)
    if rules_path:
        engine.add_rules_from(rules_path)
    if progress:
        engine.on_progress = progress
    kwargs: dict[str, Any] = {}
    if duration is not None:
        kwargs["duration"] = duration
    return engine.run_spec(spec or "demo", **kwargs)

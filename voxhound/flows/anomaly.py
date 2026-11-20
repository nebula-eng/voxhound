"""Behavioural analysis: scans, beacons, exfiltration, tunnelling.

Signature rules catch what someone already wrote down. These heuristics catch
shapes — and shapes are what you actually see first in an incident.

Each detector is deliberately simple, explainable and bounded:

* **Port scan** — one source touching N distinct destination ports on one host
  inside a short window.
* **Beaconing** — repeated contact with one host at suspiciously regular
  intervals. Measured by the coefficient of variation of inter-arrival times,
  which is scale-free: a 5 s implant and a 5 h implant both score low CV.
* **Exfiltration** — a flow whose outbound bytes dwarf inbound bytes.
* **DNS tunnelling** — many *distinct* subdomains under one parent name.

All state is capped so a 10 Gbit capture cannot grow the process without bound.
"""

from __future__ import annotations

import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from ..core.model import Alert, AppEvent, Packet, Severity


@dataclass(slots=True)
class ScanState:
    ports: dict[int, float] = field(default_factory=dict)
    last_alert: float = 0.0


@dataclass(slots=True)
class BeaconState:
    times: deque[float] = field(default_factory=lambda: deque(maxlen=32))
    last_alert: float = 0.0


class AnomalyAnalyzer:
    """Stateful, bounded behavioural detectors."""

    def __init__(
        self,
        emit: Alert,
        *,
        scan_window: float = 10.0,
        scan_threshold: int = 20,
        beacon_min_samples: int = 6,
        beacon_max_cv: float = 0.18,
        exfil_ratio: float = 20.0,
        exfil_min_bytes: int = 2 << 20,
        tunnel_threshold: int = 40,
    ) -> None:
        self._emit_cb = emit
        self.scan_window = scan_window
        self.scan_threshold = scan_threshold
        self.beacon_min_samples = beacon_min_samples
        self.beacon_max_cv = beacon_max_cv
        self.exfil_ratio = exfil_ratio
        self.exfil_min_bytes = exfil_min_bytes
        self.tunnel_threshold = tunnel_threshold

        self._scans: dict[tuple[str, str], ScanState] = {}
        self._beacons: dict[tuple[str, str], BeaconState] = {}
        self._tunnels: dict[tuple[str, str], set[str]] = defaultdict(set)
        self._alerted_flows: set[tuple[object, str]] = set()
        self.counts = {"scan": 0, "beacon": 0, "exfil": 0, "tunnel": 0}

    # ------------------------------------------------------------------ packets
    def observe_packet(self, pkt: Packet) -> None:
        if not pkt.src or pkt.ip_version == 0:
            return
        # Only SYN packets count as a *connection attempt*; data packets on an
        # already-established port would inflate the port set.
        if not (pkt.is_tcp and pkt.syn and not pkt.ack_flag):
            return
        key = (pkt.src, pkt.dst)
        state = self._scans.get(key)
        if state is None:
            if len(self._scans) > 20_000:
                self._scans.clear()
            state = ScanState()
            self._scans[key] = state
        state.ports[pkt.dport] = pkt.ts
        if len(state.ports) >= self.scan_threshold and pkt.ts - state.last_alert > 60:
            state.last_alert = pkt.ts
            self.counts["scan"] += 1
            self._emit_cb(
                Alert(
                    ts=pkt.ts,
                    rule_id="heuristic-port-scan",
                    title=f"端口扫描：{pkt.src} 在 {pkt.dst} 上探测了 {len(state.ports)} 个端口",
                    severity=int(Severity.HIGH),
                    description="短时间内命中大量不同的目的端口。",
                    flow_key=pkt.flow_key,
                    evidence={
                        "ports": len(state.ports),
                        "window_s": self.scan_window,
                        "sample": sorted(state.ports)[:16],
                    },
                )
            )
            state.ports.clear()

    # ------------------------------------------------------------------ events
    def observe_event(self, event: AppEvent, flow: object | None) -> None:
        if event.kind not in ("dns", "tls", "http", "h2", "quic"):
            return
        host = self._host_of(event, flow).rstrip(".")
        if not host:
            return
        src = flow.client_host if flow is not None else "?"
        key = (src, host)
        state = self._beacons.get(key)
        if state is None:
            if len(self._beacons) > 20_000:
                self._beacons.clear()
            state = BeaconState()
            self._beacons[key] = state
        state.times.append(event.ts)
        if len(state.times) >= self.beacon_min_samples and event.ts - state.last_alert > 120:
            if self._looks_periodic(state.times):
                state.last_alert = event.ts
                self.counts["beacon"] += 1
                intervals = [b - a for a, b in zip(list(state.times), list(state.times)[1:])]
                mean = statistics.fmean(intervals)
                cv = statistics.pstdev(intervals) / mean if mean else 0.0
                self._emit_cb(
                    Alert(
                        ts=event.ts,
                        rule_id="heuristic-beacon",
                        title=f"周期性回连 {host}，间隔约 {mean:.1f} 秒",
                        severity=int(Severity.HIGH),
                        description="联系间隔的方差极低，是 C2 心跳的典型形态。",
                        flow_key=event.flow_key,
                        evidence={
                            "host": host,
                            "interval_s": round(mean, 2),
                            "cv": round(cv, 3),
                            "samples": len(state.times),
                        },
                    )
                )
        # DNS tunnelling: many unique subdomains under one parent
        if event.kind == "dns" and event.detail.get("question"):
            self._observe_tunnel(src, str(event.detail["question"]), event)

    @staticmethod
    def _host_of(event: AppEvent, flow: object | None) -> str:
        for key in ("sni", "host", "question", "authority"):
            value = event.detail.get(key)
            if value:
                return str(value)
        if flow is not None:
            return getattr(flow, "sni", "") or ""
        return ""

    def _looks_periodic(self, times: deque[float]) -> bool:
        samples = list(times)
        intervals = [b - a for a, b in zip(samples, samples[1:])]
        if len(intervals) < self.beacon_min_samples - 1:
            return False
        if min(intervals) <= 0.5:
            return False
        mean = statistics.fmean(intervals)
        if mean < 1.0:
            return False
        cv = statistics.pstdev(intervals) / mean if mean else 1.0
        return cv <= self.beacon_max_cv

    def _observe_tunnel(self, src: str, question: str, event: AppEvent) -> None:
        labels = question.rstrip(".").split(".")
        if len(labels) < 3:
            return
        parent = ".".join(labels[-2:])
        bucket = self._tunnels[(src, parent)]
        bucket.add(".".join(labels[:-2]))
        if len(bucket) >= self.tunnel_threshold:
            self.counts["tunnel"] += 1
            self._emit_cb(
                Alert(
                    ts=event.ts,
                    rule_id="heuristic-dns-tunnel",
                    title=f"疑似 DNS 隧道：{parent}（{len(bucket)} 个唯一子域）",
                    severity=int(Severity.HIGH),
                    description="同一父域下出现高基数子域名。",
                    flow_key=event.flow_key,
                    evidence={"parent": parent, "unique": len(bucket), "sample": sorted(bucket)[:8]},
                )
            )
            bucket.clear()
        if len(self._tunnels) > 5000:
            self._tunnels.clear()

    # ------------------------------------------------------------------ flows
    def observe_flow(self, flow: object) -> None:
        up = getattr(flow, "bytes_a", 0)
        down = getattr(flow, "bytes_b", 0)
        key = getattr(flow, "key", None)
        if key is None:
            return
        # Direction 0 corresponds to the canonical first endpoint, not to the
        # client, so compare both orientations and take the worst.
        outbound, inbound = max(up, down), min(up, down)
        if outbound < self.exfil_min_bytes:
            return
        ratio = outbound / max(1, inbound)
        if ratio >= self.exfil_ratio and ("exfil", key) not in self._alerted_flows:
            self._alerted_flows.add(("exfil", key))
            self.counts["exfil"] += 1
            self._emit_cb(
                Alert(
                    ts=getattr(flow, "last_ts", time.time()),
                    rule_id="heuristic-exfil",
                    title=f"外发为主的会话 {getattr(flow, 'endpoints', lambda: '')()}："
                    f"外发 {outbound / 1048576:.1f} MiB / 接收 {inbound / 1048576:.2f} MiB",
                    severity=int(Severity.MEDIUM),
                    description="单向流量远大于另一方向。",
                    flow_key=key,
                    evidence={
                        "out_bytes": outbound,
                        "in_bytes": inbound,
                        "ratio": round(ratio, 1),
                        "app": getattr(flow, "app", ""),
                    },
                )
            )

    # ------------------------------------------------------------------ maintenance
    def tick(self, now: float) -> None:
        if now % 10 > 5:
            return
        cutoff = now - 300
        for key, state in list(self._scans.items()):
            if state.last_alert < cutoff and not state.ports:
                self._scans.pop(key, None)
        for key, state in list(self._beacons.items()):
            if state.times and state.times[-1] < cutoff:
                self._beacons.pop(key, None)


def cv_of(values: list[float]) -> float:
    """Coefficient of variation — exposed for tests and the UI tooltip."""
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    if mean == 0:
        return 0.0
    return statistics.pstdev(values) / mean

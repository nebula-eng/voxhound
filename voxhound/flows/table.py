"""Flow tracking: the stateful heart of the engine.

A flow is a bidirectional conversation keyed by ``(proto, addr_a, port_a,
addr_b, port_b)`` with the two endpoints sorted, so both directions land on the
same object without a reverse-lookup pass.

Responsibilities
----------------
* per-flow counters and timing (packets, payload bytes, first/last seen),
* TCP connection lifecycle (SYN → SYN-ACK → ACK → FIN/RST) and handshake RTT,
* host-stack fingerprinting on the SYN (JA4T + OS hint),
* attaching the right application dissector and owning its lifetime,
* bounded memory: LRU eviction of the oldest idle flow when the table is full.

The manager does *not* format anything for display and does not touch the
database; it emits events and the engine decides what to persist.
"""

from __future__ import annotations

import logging
import socket
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from ..app import registry
from ..app.base import AppSession
from ..core.model import (
    IP_PROTO_NAMES,
    AppEvent,
    Artifact,
    CaptureStats,
    FlowKey,
    Packet,
    make_flow_key,
)
from ..intel import ja4 as ja4mod
from ..intel import p0f
from ..media import carve as carve_mod
from .stream import Stream, StreamTable

log = logging.getLogger(__name__)

#: Ports that identify a service, used to pick which side is "the server".
SERVICE_PORTS = {
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    69,
    80,
    110,
    123,
    135,
    137,
    138,
    139,
    143,
    161,
    162,
    179,
    389,
    443,
    445,
    465,
    500,
    514,
    515,
    520,
    587,
    631,
    636,
    853,
    989,
    990,
    993,
    995,
    1080,
    1194,
    1433,
    1521,
    1701,
    1723,
    1812,
    1813,
    1883,
    1900,
    1935,
    2049,
    2082,
    2083,
    2086,
    2087,
    2095,
    2096,
    2181,
    2375,
    2376,
    2483,
    2484,
    3000,
    3306,
    3389,
    3478,
    3479,
    4000,
    4505,
    4506,
    5000,
    5060,
    5061,
    5222,
    5269,
    5353,
    5432,
    5555,
    5601,
    5672,
    5900,
    5938,
    5984,
    6379,
    6443,
    6667,
    7000,
    7001,
    7070,
    8000,
    8008,
    8080,
    8081,
    8086,
    8088,
    8123,
    8333,
    8443,
    8500,
    8554,
    8888,
    9000,
    9042,
    9090,
    9092,
    9200,
    9300,
    9418,
    9443,
    10000,
    11211,
    15672,
    25565,
    27017,
    50000,
    50051,
}


@dataclass(slots=True)
class Flow:
    """One observed conversation."""

    key: FlowKey
    proto: int
    first_ts: float
    last_ts: float
    src: str
    dst: str
    sport: int
    dport: int

    packets_a: int = 0
    packets_b: int = 0
    bytes_a: int = 0
    bytes_b: int = 0

    syn_seen: bool = False
    synack_seen: bool = False
    ack_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False
    closed: bool = False
    handshake_rtt_ms: float | None = None

    app: str = ""
    stream_id: int = 0
    ja4: str = ""
    ja3: str = ""
    ja4s: str = ""
    ja4t: str = ""
    os_hint: str = ""
    sni: str = ""
    alpn: str = ""
    tls_version: str = ""
    cipher: str = ""
    cert_cn: str = ""
    cert_issuer: str = ""
    dns_names: list[str] = field(default_factory=list)
    http_hosts: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    notes: dict[str, Any] = field(default_factory=dict)
    udp_app: object | None = None
    events: int = 0

    # ------------------------------------------------------------------ properties
    @property
    def proto_name(self) -> str:
        return IP_PROTO_NAMES.get(self.proto, f"IP-{self.proto}")

    @property
    def packets(self) -> int:
        return self.packets_a + self.packets_b

    @property
    def payload_bytes(self) -> int:
        return self.bytes_a + self.bytes_b

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def service_port(self) -> int:
        """Which port looks like the server side."""
        if self.dport in SERVICE_PORTS and self.sport not in SERVICE_PORTS:
            return self.dport
        if self.sport in SERVICE_PORTS and self.dport not in SERVICE_PORTS:
            return self.sport
        return min(self.sport, self.dport) if min(self.sport, self.dport) < 32768 else self.dport

    @property
    def service_host(self) -> str:
        return self.dst if self.service_port == self.dport else self.src

    @property
    def client_host(self) -> str:
        return self.src if self.service_port == self.dport else self.dst

    def endpoints(self) -> str:
        return f"{endpoint(self.src, self.sport)} ↔ {endpoint(self.dst, self.dport)}"

    def label(self) -> str:
        host = (
            self.sni
            or (self.dns_names[0] if self.dns_names else "")
            or (self.http_hosts[0] if self.http_hosts else "")
        )
        suffix = f" {host}" if host else ""
        return f"{self.app or self.proto_name}{suffix}"

    def row(self) -> dict[str, Any]:
        """Flat dict for tables, CSV and the SQLite store."""
        return {
            "src": self.src,
            "sport": self.sport,
            "dst": self.dst,
            "dport": self.dport,
            "proto": self.proto_name,
            "app": self.app,
            "sni": self.sni,
            "ja3": self.ja3,
            "ja4": self.ja4,
            "ja4s": self.ja4s,
            "ja4t": self.ja4t,
            "os": self.os_hint,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "cert_cn": self.cert_cn,
            "packets": self.packets,
            "bytes": self.payload_bytes,
            "duration": round(self.duration, 3),
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "state": "closed" if (self.closed or self.rst_seen) else "open",
            "tags": ",".join(self.tags),
            "rtt_ms": round(self.handshake_rtt_ms, 2) if self.handshake_rtt_ms is not None else None,
        }


class FlowManager:
    """Owns the flow table, the stream table and dissector lifetimes."""

    def __init__(
        self,
        *,
        on_event: Callable[[AppEvent], None],
        on_artifact: Callable[[Artifact], None],
        stats: CaptureStats | None = None,
        max_flows: int = 120_000,
        idle_timeout: float = 300.0,
        udp_timeout: float = 60.0,
        carve_streams: bool = True,
    ) -> None:
        self.flows: dict[FlowKey, Flow] = {}
        self.streams = StreamTable()
        self.on_event = on_event
        self.on_artifact = on_artifact
        self.stats = stats or CaptureStats()
        self.max_flows = max_flows
        self.idle_timeout = idle_timeout
        self.udp_timeout = udp_timeout
        self.carve_streams = carve_streams
        self._addr_cache: dict[str, bytes] = {}
        self._syn_ts: dict[FlowKey, tuple[float, int]] = {}
        self.new_flows = 0
        self.closed_flows = 0
        self.evicted = 0
        self.dissector_errors = 0

    # ------------------------------------------------------------------ helpers
    def _pack(self, addr: str) -> bytes:
        cached = self._addr_cache.get(addr)
        if cached is not None:
            return cached
        try:
            raw = socket.inet_pton(socket.AF_INET6 if ":" in addr else socket.AF_INET, addr)
        except (OSError, ValueError):
            raw = addr.encode()
        if len(self._addr_cache) > 20_000:
            self._addr_cache.clear()
        self._addr_cache[addr] = raw
        return raw

    def _emit(self, event: AppEvent) -> None:
        self.on_event(event)

    # ------------------------------------------------------------------ main entry
    def process(self, pkt: Packet) -> Flow | None:
        src_raw = self._pack(pkt.src) if pkt.src else b""
        dst_raw = self._pack(pkt.dst) if pkt.dst else b""
        key, direction = make_flow_key(pkt.proto, src_raw, pkt.sport, dst_raw, pkt.dport)
        pkt.flow_key = key
        pkt.direction = direction

        flow = self.flows.get(key)
        if flow is None:
            flow = self._create_flow(pkt, key)
        flow.last_ts = pkt.ts
        if direction == 0:
            flow.packets_a += 1
            flow.bytes_a += pkt.payload_len
        else:
            flow.packets_b += 1
            flow.bytes_b += pkt.payload_len
        pkt.app = flow.app or flow.proto_name

        if pkt.is_tcp:
            self._tcp(flow, pkt, direction)
        elif pkt.is_udp:
            self._udp(flow, pkt, direction)
        return flow

    def _create_flow(self, pkt: Packet, key: FlowKey) -> Flow:
        if len(self.flows) >= self.max_flows:
            self._evict()
        flow = Flow(
            key=key,
            proto=pkt.proto,
            first_ts=pkt.ts,
            last_ts=pkt.ts,
            src=pkt.src,
            dst=pkt.dst,
            sport=pkt.sport,
            dport=pkt.dport,
        )
        self.flows[key] = flow
        self.new_flows += 1
        return flow

    def _evict(self) -> None:
        """Drop the least recently used flow that is already closed, else the oldest."""
        if not self.flows:
            return
        candidates = [(f.last_ts, k) for k, f in self.flows.items() if f.closed or f.rst_seen]
        if not candidates:
            candidates = [(f.last_ts, k) for k, f in self.flows.items()]
        _ts, key = min(candidates)
        self._close_flow(key, self.flows[key].last_ts, emit=False)
        self.evicted += 1

    # ------------------------------------------------------------------ TCP
    def _tcp(self, flow: Flow, pkt: Packet, direction: int) -> None:
        if pkt.syn and not pkt.ack_flag:
            flow.syn_seen = True
            self._syn_ts[flow.key] = (pkt.ts, direction)
            if not flow.ja4t:
                flow.ja4t = ja4mod.compute_ja4t(
                    window=pkt.win,
                    options=[kind for kind, _length in pkt.tcp_opts],
                    mss=pkt.mss,
                    window_scale=pkt.wscale,
                )
                guess = p0f.guess_os(ttl=pkt.ttl, mss=pkt.mss, wscale=pkt.wscale, opt_sig=pkt.opt_sig)
                flow.os_hint = guess.label
                flow.notes["os_reason"] = guess.reason
                flow.notes["os_confidence"] = round(guess.confidence, 2)
            return
        if pkt.syn and pkt.ack_flag:
            flow.synack_seen = True
            syn = self._syn_ts.get(flow.key)
            if syn and syn[1] != direction:
                flow.handshake_rtt_ms = (pkt.ts - syn[0]) * 1000.0
            return
        if pkt.ack_flag and not pkt.syn:
            if flow.synack_seen:
                flow.ack_seen = True
            if pkt.payload_len:
                flow.ack_seen = True

        stream = self.streams.get_or_create(flow.key, pkt.ts)
        if not flow.stream_id:
            flow.stream_id = stream.id
        if pkt.payload_len:
            payload = bytes(pkt.payload)
            try:
                if stream.app is None:
                    self._attach_stream_app(flow, stream, payload, direction, pkt.ts)
                stream.push(direction, pkt.seq, payload, pkt.ts, syn=pkt.syn)
            except Exception:  # noqa: BLE001 - a dissector bug must not stop the capture
                self.dissector_errors += 1
                log.warning("dissector failed on %s; dropping it for this flow", flow.app, exc_info=True)
                stream.app = None
                flow.tags.append("dissector-error")
        elif pkt.syn:
            stream.push(direction, pkt.seq, b"", pkt.ts, syn=True)

        if pkt.fin or pkt.rst:
            if pkt.rst:
                flow.rst_seen = True
                flow.notes["reset"] = True
            flow.fin_seen = True
            self._close_flow(flow.key, pkt.ts)

    def _attach_stream_app(
        self, flow: Flow, stream: Stream, payload: bytes, direction: int, ts: float
    ) -> None:
        session = AppSession(
            flow,
            stream,
            event_sink=self._emit,
            artifact_sink=self.on_artifact,
            ts=ts,
            kind="stream",
        )
        dissector = registry.make_stream_dissector(flow, stream, payload, direction, session)
        if dissector is None:
            return
        stream.app = dissector
        stream.app_name = dissector.name
        if not flow.app:
            flow.app = dissector.name

    # ------------------------------------------------------------------ UDP
    def _udp(self, flow: Flow, pkt: Packet, direction: int) -> None:
        payload = bytes(pkt.payload)
        if not payload:
            return
        app = flow.udp_app
        if app is None:
            session = AppSession(
                flow,
                None,
                event_sink=self._emit,
                artifact_sink=self.on_artifact,
                ts=pkt.ts,
                kind="datagram",
            )
            app = registry.make_datagram_dissector(flow, payload, session)
            flow.udp_app = app
            if app is not None and not flow.app:
                flow.app = app.name
        if app is None:
            return
        session = app.s  # type: ignore[attr-defined]
        session.ts = pkt.ts
        try:
            app.feed(direction, payload)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - one bad datagram must not stop the capture
            log.debug("datagram dissector failed", exc_info=True)
            flow.udp_app = None

    # ------------------------------------------------------------------ closing
    def _close_flow(self, key: FlowKey, ts: float, *, emit: bool = True) -> None:
        flow = self.flows.get(key)
        if flow is None or flow.closed:
            return
        flow.closed = True
        self.closed_flows += 1
        app = flow.udp_app
        if app is not None and hasattr(app, "close"):
            try:
                app.close()
            except Exception:  # noqa: BLE001
                log.debug("dissector close failed", exc_info=True)
        stream = self.streams.get(key)
        if stream is not None:
            stream.close(ts)
            if self.carve_streams:
                self._carve(flow, stream)
            self.streams.close(key, ts)
        if emit:
            duration = max(0.0, ts - flow.first_ts)
            self._emit(
                AppEvent(
                    ts=ts,
                    kind="flow",
                    title=f"{flow.label()} 会话结束 · {flow.packets} 包 · "
                    f"{flow.payload_bytes / 1024:.1f} KiB · {duration:.1f} 秒",
                    flow_key=key,
                    detail={"flow": flow.row()},
                )
            )

    def _carve(self, flow: Flow, stream: Stream) -> None:
        if flow.app in ("HTTP", "HTTP/2", "TLS", "WebSocket"):
            return  # these dissectors already carve their own payloads
        candidates: list[bytes] = []
        for direction in (0, 1):
            blob = bytes(stream.preview[direction])
            if len(blob) >= 64:
                candidates.append(blob)
        for blob in candidates:
            try:
                blobs = carve_mod.scan(blob)
            except Exception:  # noqa: BLE001
                continue
            for artifact in carve_mod.make_artifacts(
                blobs, stream_id=stream.id, flow_key=flow.key, source=f"stream:{flow.app or 'raw'}"
            ):
                artifact.ts = flow.last_ts
                self.on_artifact(artifact)

    # ------------------------------------------------------------------ maintenance
    def expire(self, now: float) -> int:
        """Close idle flows; returns how many were closed this round."""
        expired = 0
        for key, flow in list(self.flows.items()):
            if flow.closed:
                # Closed flows stay for reporting; memory is bounded by
                # ``max_flows`` plus LRU eviction, which prefers closed flows.
                continue
            timeout = self.udp_timeout if flow.proto == 17 else self.idle_timeout
            if now - flow.last_ts > timeout:
                self._close_flow(key, flow.last_ts, emit=True)
                expired += 1
        for stream in self.streams.streams.values():
            stream.tick(now)
        return expired

    def close_all(self, ts: float) -> None:
        for key in list(self.flows):
            self._close_flow(key, max(ts, self.flows[key].last_ts))

    def prune_closed(self, keep_last: float = 300.0, *, now: float | None = None) -> int:
        """Drop closed flows older than ``keep_last`` seconds of capture time."""
        current = now if now is not None else time.time()
        stale = [k for k, f in self.flows.items() if f.closed and current - f.last_ts > keep_last]
        for key in stale:
            self.flows.pop(key, None)
        return len(stale)

    # ------------------------------------------------------------------ accessors
    def __len__(self) -> int:
        return len(self.flows)

    def iter_flows(self, *, include_closed: bool = True) -> Iterator[Flow]:
        for flow in self.flows.values():
            if include_closed or not flow.closed:
                yield flow

    def find(self, key: FlowKey) -> Flow | None:
        return self.flows.get(key)

    def summary(self) -> dict[str, int]:
        return {
            "flows": len(self.flows),
            "open_flows": sum(1 for f in self.flows.values() if not f.closed),
            "streams": len(self.streams),
            "new_flows": self.new_flows,
            "closed_flows": self.closed_flows,
            "evicted": self.evicted,
        }


def endpoint(addr: str, port: int) -> str:
    """Bracket IPv6 literals so ``host:port`` stays unambiguous."""
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"

"""Core data model shared by every layer.

Design notes
------------
* ``RawPacket`` owns bytes exactly once. The decoder hands out ``memoryview``
  slices; nothing downstream may keep a view alive after ``decode()`` returns,
  otherwise the whole capture buffer of a 1 GiB file would be pinned in memory.
  Reassembly therefore copies into ``bytes`` at the boundary.
* ``Packet`` is a slotted dataclass: at 200k packets/s of decode throughput the
  per-object dict overhead of a normal class is the first thing that hurts.
* Flow identity is a plain tuple of primitives so it can be used directly as a
  dict key and serialised without adapters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Final

# --------------------------------------------------------------------------- link types
LINKTYPE_NULL: Final = 0
LINKTYPE_ETHERNET: Final = 1
LINKTYPE_RAW: Final = 101
LINKTYPE_IEEE802_11: Final = 105
LINKTYPE_LINUX_SLL: Final = 113
LINKTYPE_IPV4: Final = 228
LINKTYPE_IPV6: Final = 229
LINKTYPE_LINUX_SLL2: Final = 276

LINKTYPE_NAMES: Final = {
    LINKTYPE_NULL: "NULL/Loopback",
    LINKTYPE_ETHERNET: "Ethernet",
    LINKTYPE_RAW: "Raw IP",
    LINKTYPE_IEEE802_11: "IEEE 802.11",
    LINKTYPE_LINUX_SLL: "Linux cooked v1",
    LINKTYPE_IPV4: "Raw IPv4",
    LINKTYPE_IPV6: "Raw IPv6",
    LINKTYPE_LINUX_SLL2: "Linux cooked v2",
}

# --------------------------------------------------------------------------- L3/L4 numbers
IPPROTO_ICMP: Final = 1
IPPROTO_IGMP: Final = 2
IPPROTO_TCP: Final = 6
IPPROTO_UDP: Final = 17
IPPROTO_GRE: Final = 47
IPPROTO_ESP: Final = 50
IPPROTO_AH: Final = 51
IPPROTO_ICMPV6: Final = 58
IPPROTO_SCTP: Final = 132

IP_PROTO_NAMES: Final = {
    IPPROTO_ICMP: "ICMP",
    IPPROTO_IGMP: "IGMP",
    IPPROTO_TCP: "TCP",
    IPPROTO_UDP: "UDP",
    IPPROTO_GRE: "GRE",
    IPPROTO_ESP: "ESP",
    IPPROTO_AH: "AH",
    IPPROTO_ICMPV6: "ICMPv6",
    IPPROTO_SCTP: "SCTP",
}


class TcpFlag(IntEnum):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


_FLAG_ORDER = (
    (TcpFlag.SYN, "S"),
    (TcpFlag.ACK, "A"),
    (TcpFlag.PSH, "P"),
    (TcpFlag.FIN, "F"),
    (TcpFlag.RST, "R"),
    (TcpFlag.URG, "U"),
    (TcpFlag.ECE, "E"),
    (TcpFlag.CWR, "C"),
)


def tcp_flag_str(flags: int) -> str:
    """Render flags in Wireshark's conventional order (SYN, ACK, PSH, FIN, RST…)."""
    return "".join(label for bit, label in _FLAG_ORDER if flags & bit) or "-"


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return _SEVERITY_LABEL[int(self)]

    @property
    def english(self) -> str:
        """稳定的英文标识，供 JSON/日志等机器可读场景使用。"""
        return ("info", "low", "medium", "high", "critical")[int(self)]


_SEVERITY_LABEL: Final = {
    0: "信息",
    1: "较低",
    2: "中",
    3: "高",
    4: "严重",
}


@dataclass(slots=True)
class RawPacket:
    """One captured frame, budgeted by the source before it enters the pipeline."""

    ts: float
    data: bytes
    caplen: int
    wirelen: int
    linktype: int = LINKTYPE_ETHERNET
    ifindex: int = 0

    @property
    def truncated(self) -> bool:
        return self.caplen < self.wirelen

    def __len__(self) -> int:
        return self.caplen


#: (ip protocol, endpoint A, endpoint B) where an endpoint is ``(addr_bytes, port)``
#: and the two are ordered so both directions hash to the same key.
FlowKey = tuple[int, bytes, int, bytes, int]


def make_flow_key(proto: int, src: bytes, sport: int, dst: bytes, dport: int) -> tuple[FlowKey, int]:
    """Return ``(key, direction)`` with ``direction`` 0 when ``src`` is the low side.

    Comparing ``(addr, port)`` pairs keeps the key symmetric for the two
    directions of a conversation without allocating extra objects beyond the
    tuple itself.
    """
    a = (src, sport)
    b = (dst, dport)
    if a <= b:
        return (proto, src, sport, dst, dport), 0
    return (proto, dst, dport, src, sport), 1


@dataclass(slots=True)
class Packet:
    """A decoded frame. ``info`` is a one-line human summary, Wireshark style."""

    number: int = 0
    ts: float = 0.0
    caplen: int = 0
    wirelen: int = 0
    linktype: int = LINKTYPE_ETHERNET

    eth_src: str = ""
    eth_dst: str = ""
    vlan: tuple[int, ...] = ()

    ip_version: int = 0
    src: str = ""
    dst: str = ""
    ttl: int = 0
    ip_id: int = -1
    ip_len: int = 0
    frag: str = ""
    tos: int = 0

    proto: int = 0
    proto_name: str = ""
    sport: int = 0
    dport: int = 0

    tcp_flags: int = 0
    seq: int = 0
    ack: int = 0
    win: int = 0
    tcp_hdr_len: int = 0
    tcp_opts: tuple[tuple[int, int], ...] = ()
    mss: int = 0
    wscale: int = -1
    ts_val: int = -1
    ts_ecr: int = -1
    opt_sig: str = ""

    payload_len: int = 0
    payload: memoryview = field(default_factory=lambda: memoryview(b""))

    flow_key: FlowKey | None = None
    direction: int = 0

    info: str = ""
    app: str = ""
    layers: tuple[str, ...] = ()
    malformed: str = ""

    # ------------------------------------------------------------------ helpers
    @property
    def is_tcp(self) -> bool:
        return self.proto == IPPROTO_TCP

    @property
    def is_udp(self) -> bool:
        return self.proto == IPPROTO_UDP

    @property
    def syn(self) -> bool:
        return bool(self.tcp_flags & TcpFlag.SYN)

    @property
    def ack_flag(self) -> bool:
        return bool(self.tcp_flags & TcpFlag.ACK)

    @property
    def fin(self) -> bool:
        return bool(self.tcp_flags & TcpFlag.FIN)

    @property
    def rst(self) -> bool:
        return bool(self.tcp_flags & TcpFlag.RST)

    @property
    def dst_port_key(self) -> tuple[str, int]:
        return (self.dst, self.dport)

    def summary(self) -> str:
        """Compact one-liner used in the packet list when ``info`` is empty."""
        if self.proto_name in ("TCP", "UDP"):
            return f"{self.sport} → {self.dport} [{self.payload_len} B] {tcp_flag_str(self.tcp_flags)}"
        return f"{self.proto_name} {self.src} → {self.dst}"


@dataclass(slots=True)
class CaptureStats:
    """Counters shared by sources, the pipeline and the UI status bar."""

    packets: int = 0
    bytes: int = 0
    wire_bytes: int = 0
    dropped: int = 0
    if_dropped: int = 0
    errors: int = 0
    malformed: int = 0
    started_at: float = 0.0
    first_ts: float = 0.0
    last_ts: float = 0.0
    capture_filter: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "wire_bytes": self.wire_bytes,
            "dropped": self.dropped,
            "if_dropped": self.if_dropped,
            "errors": self.errors,
            "malformed": self.malformed,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "capture_filter": self.capture_filter,
        }


@dataclass(slots=True)
class AppEvent:
    """A protocol-level observation emitted by a dissector.

    The UI renders these as the "activity" stream, the rule engine evaluates
    them, and ``store.sqlite`` persists the interesting ones.
    """

    ts: float
    kind: str
    title: str
    flow_key: FlowKey | None = None
    severity: int = 0
    detail: dict[str, Any] = field(default_factory=dict)

    def line(self) -> str:
        bits = [self.kind, self.title]
        if self.flow_key:
            bits.append(
                f"{_addr_text(self.flow_key[1])}:{self.flow_key[2]} ↔ {_addr_text(self.flow_key[3])}:{self.flow_key[4]}"
            )
        return " | ".join(bits)


def _addr_text(raw: bytes) -> str:
    if len(raw) == 4:
        return ".".join(str(b) for b in raw)
    if len(raw) == 16:
        return ":".join(f"{raw[i] << 8 | raw[i + 1]:x}" for i in range(0, 16, 2))
    return raw.hex()


@dataclass(slots=True)
class Artifact:
    """A payload carved out of traffic: an audio call, an image, a document."""

    ts: float
    kind: str
    name: str
    data: bytes
    source: str
    flow_key: FlowKey | None = None
    stream_id: int = 0
    meta: dict[str, Any] = field(default_factory=dict)
    sha256: str = ""

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass(slots=True)
class Alert:
    """A rule hit or heuristic finding."""

    ts: float
    rule_id: str
    title: str
    severity: int
    description: str = ""
    flow_key: FlowKey | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def severity_label(self) -> str:
        return _SEVERITY_LABEL.get(int(self.severity), "info")

"""ICMP and ICMPv6: enough to read diagnostics and tunnel detection signals."""

from __future__ import annotations

import struct
from dataclasses import dataclass

ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACH = 3
ICMP_SOURCE_QUENCH = 4
ICMP_REDIRECT = 5
ICMP_ECHO_REQUEST = 8
ICMP_ROUTER_ADVERT = 9
ICMP_ROUTER_SOLICIT = 10
ICMP_TIME_EXCEEDED = 11
ICMP_PARAM_PROBLEM = 12
ICMP_TIMESTAMP = 13
ICMP_TIMESTAMP_REPLY = 14

ICMP_TYPES = {
    0: "Echo reply",
    3: "Destination unreachable",
    4: "Source quench",
    5: "Redirect",
    8: "Echo request",
    9: "Router advertisement",
    10: "Router solicitation",
    11: "Time exceeded",
    12: "Parameter problem",
    13: "Timestamp request",
    14: "Timestamp reply",
    17: "Address mask request",
    18: "Address mask reply",
}

ICMP_CODE_UNREACH = {
    0: "net unreachable",
    1: "host unreachable",
    2: "protocol unreachable",
    3: "port unreachable",
    4: "fragmentation needed",
    5: "source route failed",
    9: "network administratively prohibited",
    10: "host administratively prohibited",
    13: "communication administratively filtered",
}

ICMPV6_TYPES = {
    1: "Destination unreachable",
    2: "Packet too big",
    3: "Time exceeded",
    4: "Parameter problem",
    128: "Echo request",
    129: "Echo reply",
    133: "Router solicitation",
    134: "Router advertisement",
    135: "Neighbor solicitation",
    136: "Neighbor advertisement",
    137: "Redirect",
}


@dataclass(slots=True)
class IcmpMessage:
    type: int
    code: int
    checksum: int
    rest: bytes
    version: int = 4

    @property
    def label(self) -> str:
        table = ICMPV6_TYPES if self.version == 6 else ICMP_TYPES
        return table.get(self.type, f"type {self.type}")

    @property
    def echo_ident(self) -> int | None:
        if self.version == 4 and self.type in (ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY) and len(self.rest) >= 4:
            return struct.unpack_from("!H", self.rest, 0)[0]
        if self.version == 6 and self.type in (128, 129) and len(self.rest) >= 4:
            return struct.unpack_from("!H", self.rest, 0)[0]
        return None

    @property
    def echo_seq(self) -> int | None:
        if self.version == 4 and self.type in (ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY) and len(self.rest) >= 4:
            return struct.unpack_from("!H", self.rest, 2)[0]
        if self.version == 6 and self.type in (128, 129) and len(self.rest) >= 4:
            return struct.unpack_from("!H", self.rest, 2)[0]
        return None

    def summary(self) -> str:
        parts = [self.label]
        if self.version == 4 and self.type == ICMP_DEST_UNREACH or self.version == 6 and self.type == 1:
            parts.append(ICMP_CODE_UNREACH.get(self.code, f"code {self.code}"))
        if self.echo_ident is not None:
            parts.append(f"id=0x{self.echo_ident:04x} seq={self.echo_seq}")
        return " ".join(parts)


def parse(buf: bytes | memoryview, version: int = 4) -> IcmpMessage:
    if len(buf) < 4:
        raise ValueError("short ICMP header")
    mtype, code, checksum = struct.unpack_from("!BBH", buf, 0)
    return IcmpMessage(
        type=mtype, code=code, checksum=checksum, rest=bytes(memoryview(buf)[4:]), version=version
    )

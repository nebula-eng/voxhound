"""Link-layer decoding for every link type we advertise support for.

Ethernet with stacked VLAN tags (802.1Q / 802.1ad), MPLS label stacks, PPPoE,
802.3 LLC/SNAP, Linux cooked captures, BSD loopback and raw IP links. Anything
we cannot interpret sets ``pkt.malformed`` and stops — a decoder that guesses is
worse than one that admits defeat.
"""

from __future__ import annotations

import struct

from ..core.model import (
    LINKTYPE_ETHERNET,
    LINKTYPE_IPV4,
    LINKTYPE_IPV6,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_NULL,
    LINKTYPE_RAW,
    Packet,
)

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_VLAN = 0x8100
ETH_QINQ = 0x88A8
ETH_IPV6 = 0x86DD
ETH_MPLS = 0x8847
ETH_MPLS_MC = 0x8848
ETH_PPPOE_SESSION = 0x8864

IPV4_ETHERTYPES = {ETH_IPV4}
IPV6_ETHERTYPES = {ETH_IPV6}


class LinkResult:
    """Where the L3 payload starts and what it claims to be."""

    __slots__ = ("ethertype", "payload", "label", "arp")

    def __init__(
        self, ethertype: int, payload: memoryview, label: str, arp: dict[str, str] | None = None
    ) -> None:
        self.ethertype = ethertype
        self.payload = payload
        self.label = label
        self.arp = arp


def decode_link(pkt: Packet, buf: bytes | memoryview) -> LinkResult:
    view = memoryview(buf)
    link = pkt.linktype

    if link == LINKTYPE_ETHERNET:
        return _ethernet(pkt, view)
    if link == LINKTYPE_NULL:
        return _null(pkt, view)
    if link == LINKTYPE_RAW:
        return _raw_ip(view)
    if link == LINKTYPE_LINUX_SLL:
        if len(view) < 16:
            raise ValueError("short Linux SLL header")
        proto = struct.unpack_from("!H", view, 14)[0]
        pkt.layers = (*pkt.layers, "SLL")
        return LinkResult(proto, view[16:], "Linux SLL")
    if link == LINKTYPE_LINUX_SLL2:
        if len(view) < 20:
            raise ValueError("short Linux SLL2 header")
        proto = struct.unpack_from("!H", view, 0)[0]
        pkt.layers = (*pkt.layers, "SLL2")
        return LinkResult(proto, view[20:], "Linux SLL2")
    if link == LINKTYPE_IPV4:
        return LinkResult(ETH_IPV4, view, "Raw IPv4")
    if link == LINKTYPE_IPV6:
        return LinkResult(ETH_IPV6, view, "Raw IPv6")
    raise ValueError(f"unsupported link type {link}")


def _ethernet(pkt: Packet, view: memoryview) -> LinkResult:
    if len(view) < 14:
        raise ValueError("short Ethernet frame")
    pkt.eth_dst = ":".join(f"{b:02x}" for b in view[0:6])
    pkt.eth_src = ":".join(f"{b:02x}" for b in view[6:12])
    ethertype = struct.unpack_from("!H", view, 12)[0]
    offset = 14
    layers = ["Ethernet"]
    tags: list[int] = []
    while ethertype in (ETH_VLAN, ETH_QINQ):
        if len(view) < offset + 4:
            raise ValueError("truncated VLAN tag")
        tci, ethertype = struct.unpack_from("!HH", view, offset)
        tags.append(tci & 0x0FFF)
        offset += 4
        layers.append("802.1Q" if len(tags) == 1 else "802.1ad")
    pkt.vlan = tuple(tags)

    if ethertype in (ETH_MPLS, ETH_MPLS_MC):
        # Walk the label stack until bottom-of-stack; then sniff IP by version.
        while len(view) >= offset + 4:
            entry = struct.unpack_from("!I", view, offset)[0]
            offset += 4
            if entry & 0x100:
                break
        layers.append("MPLS")
        if len(view) <= offset:
            raise ValueError("MPLS stack without payload")
        version = view[offset] >> 4
        ethertype = ETH_IPV4 if version == 4 else ETH_IPV6 if version == 6 else 0
    elif ethertype <= 1500:  # 802.3 length field -> LLC/SNAP
        layers.append("802.3")
        if len(view) >= offset + 8 and view[offset : offset + 3] == b"\xaa\xaa\x03":
            ethertype = struct.unpack_from("!H", view, offset + 6)[0]
            offset += 8
            layers.append("SNAP")
        else:
            return LinkResult(0, view[offset:], "802.3 LLC", arp=None)
    elif ethertype == ETH_PPPOE_SESSION:
        layers.append("PPPoE")
        if len(view) < offset + 8:
            raise ValueError("truncated PPPoE header")
        ppp_proto = struct.unpack_from("!H", view, offset + 6)[0]
        offset += 8
        ethertype = ETH_IPV4 if ppp_proto == 0x0021 else ETH_IPV6 if ppp_proto == 0x0057 else 0
        layers.append("PPP")

    pkt.layers = tuple(layers)
    if ethertype == ETH_ARP:
        return LinkResult(ethertype, view[offset:], "ARP", arp=_parse_arp(view[offset:]))
    return LinkResult(ethertype, view[offset:], "Ethernet")


def _null(pkt: Packet, view: memoryview) -> LinkResult:
    if len(view) < 4:
        raise ValueError("short loopback header")
    family = struct.unpack_from("<I", view, 0)[0]
    if family not in (2, 24, 28, 30):
        family = struct.unpack_from(">I", view, 0)[0]
    pkt.layers = ("Loopback",)
    if family == 2:
        return LinkResult(ETH_IPV4, view[4:], "Loopback")
    if family in (24, 28, 30):
        return LinkResult(ETH_IPV6, view[4:], "Loopback")
    raise ValueError(f"unknown loopback family {family}")


def _raw_ip(view: memoryview) -> LinkResult:
    if not view:
        raise ValueError("empty raw IP payload")
    version = view[0] >> 4
    if version == 4:
        return LinkResult(ETH_IPV4, view, "Raw IP")
    if version == 6:
        return LinkResult(ETH_IPV6, view, "Raw IP")
    raise ValueError(f"raw link with IP version {version}")


ARP_OPCODES = {1: "request", 2: "reply", 3: "RARP request", 4: "RARP reply"}


def _parse_arp(buf: memoryview) -> dict[str, str]:
    if len(buf) < 8:
        return {}
    htype, ptype, _hlen, _plen, opcode = struct.unpack_from("!HHBBH", buf, 0)
    info: dict[str, str] = {
        "opcode": ARP_OPCODES.get(opcode, str(opcode)),
        "hw": "Ethernet" if htype == 1 else str(htype),
        "proto": "IPv4" if ptype == ETH_IPV4 else f"0x{ptype:04x}",
    }
    if ptype == ETH_IPV4 and len(buf) >= 28:
        info["sender_ip"] = ".".join(str(b) for b in buf[14:18])
        info["target_ip"] = ".".join(str(b) for b in buf[24:28])
        info["sender_mac"] = ":".join(f"{b:02x}" for b in buf[8:14])
    return info

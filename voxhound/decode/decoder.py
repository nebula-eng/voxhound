"""The decoder: bytes in, a :class:`~voxhound.core.model.Packet` out.

Deliberate behaviours
---------------------
* **Never raises** for hostile input. Every parse failure is turned into
  ``pkt.malformed`` with a short reason, because capture files come from
  untrusted networks and a fuzzed packet must not kill an analysis run.
* **Reassembly happens here**, not in the flow layer: fragments are a property
  of the IP layer, and handing a half-datagram to TCP would corrupt sequence
  space arithmetic.
* **Checksums are optional** and off by default for live capture.
"""

from __future__ import annotations

import logging

from ..core.model import (
    IP_PROTO_NAMES,
    IPPROTO_ICMP,
    IPPROTO_ICMPV6,
    IPPROTO_TCP,
    IPPROTO_UDP,
    Packet,
    RawPacket,
    tcp_flag_str,
)
from . import checksum, icmp, ipv4, ipv6, link, tcp, udp
from .frag import IPv6Defragmenter

log = logging.getLogger(__name__)

ETH_ARP = 0x0806
ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD

TCP_FLAG_NAMES = {0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH", 0x10: "ACK", 0x20: "URG"}


class Decoder:
    """Stateful because fragment reassembly needs memory."""

    def __init__(self, *, verify_checksums: bool = False) -> None:
        self.verify_checksums = verify_checksums
        self._v4_frag = ipv4.IPv4Defragmenter()
        self._v6_frag = IPv6Defragmenter()
        self.stats = {"fragments": 0, "reassembled": 0, "malformed": 0, "checksum_errors": 0}

    # ------------------------------------------------------------------ entry
    def decode(self, raw: RawPacket, number: int) -> Packet | None:
        pkt = Packet(
            number=number,
            ts=raw.ts,
            caplen=raw.caplen,
            wirelen=raw.wirelen,
            linktype=raw.linktype,
        )
        try:
            result = link.decode_link(pkt, raw.data)
        except ValueError as exc:
            return self._malformed(pkt, f"link layer: {exc}")

        if result.arp is not None:
            pkt.proto_name = "ARP"
            pkt.layers = (*pkt.layers, "ARP")
            opcode = result.arp.get("opcode", "")
            src = result.arp.get("sender_ip", "?")
            tgt = result.arp.get("target_ip", "?")
            pkt.src, pkt.dst = src, tgt
            pkt.info = (
                f"ARP {opcode}: {src} is at {result.arp.get('sender_mac', '?')}"
                if opcode == "reply"
                else f"ARP {opcode}: who has {tgt}? tell {src}"
            )
            pkt.payload = result.payload
            pkt.payload_len = len(result.payload)
            return pkt

        if result.ethertype == ETH_IPV4:
            return self._ipv4(pkt, result.payload, raw.ts)
        if result.ethertype == ETH_IPV6:
            return self._ipv6(pkt, result.payload, raw.ts)

        pkt.layers = (*pkt.layers, f"0x{result.ethertype:04x}")
        pkt.payload = result.payload
        pkt.payload_len = len(result.payload)
        pkt.info = f"EtherType 0x{result.ethertype:04x} ({len(result.payload)} B)"
        return pkt

    # ------------------------------------------------------------------ IPv4
    def _ipv4(self, pkt: Packet, buf: memoryview, ts: float) -> Packet:
        try:
            hdr = ipv4.parse(buf)
        except ValueError as exc:
            return self._malformed(pkt, f"IPv4: {exc}")

        pkt.ip_version = 4
        pkt.src = ipv4.format_addr(hdr.src)
        pkt.dst = ipv4.format_addr(hdr.dst)
        pkt.ttl = hdr.ttl
        pkt.tos = hdr.tos
        pkt.ip_id = hdr.ident
        pkt.ip_len = hdr.total_len
        pkt.layers = (*pkt.layers, "IPv4")
        if self.verify_checksums and not checksum.verify_ipv4_header(buf[: hdr.header_len]):
            pkt.malformed = "bad IPv4 header checksum"
            self.stats["checksum_errors"] += 1

        segment = ipv4.payload_view(buf, hdr)
        if hdr.is_fragment:
            self.stats["fragments"] += 1
            pkt.frag = f"offset={hdr.frag_offset} mf={int(hdr.more_fragments)} id={hdr.ident:#06x}"
            assembled = self._v4_frag.add(hdr, bytes(segment), now=ts)
            if assembled is None:
                pkt.info = f"IPv4 fragment {pkt.frag} ({len(segment)} B)"
                pkt.payload = segment
                pkt.payload_len = len(segment)
                return pkt
            self.stats["reassembled"] += 1
            pkt.frag = "reassembled"
            segment = memoryview(assembled)

        return self._transport(pkt, segment, hdr.proto, src=hdr.src, dst=hdr.dst)

    # ------------------------------------------------------------------ IPv6
    def _ipv6(self, pkt: Packet, buf: memoryview, ts: float) -> Packet:
        try:
            hdr, proto, segment = ipv6.parse(buf)
        except ValueError as exc:
            return self._malformed(pkt, f"IPv6: {exc}")

        pkt.ip_version = 6
        pkt.src = ipv6.format_addr(hdr.src)
        pkt.dst = ipv6.format_addr(hdr.dst)
        pkt.ttl = hdr.hop_limit
        pkt.ip_len = hdr.payload_len + 40
        pkt.tos = hdr.traffic_class
        pkt.layers = (*pkt.layers, "IPv6")
        if hdr.has_fragment:
            self.stats["fragments"] += 1
            pkt.frag = f"offset={hdr.frag_offset} mf={int(hdr.more_fragments)} id={hdr.frag_id:#010x}"
            assembled = self._v6_frag.add(
                bytes(hdr.src),
                bytes(hdr.dst),
                hdr.frag_id,
                proto,
                hdr.frag_offset,
                hdr.more_fragments,
                bytes(segment),
                now=ts,
            )
            if assembled is None:
                pkt.info = f"IPv6 fragment {pkt.frag} ({len(segment)} B)"
                pkt.payload = segment
                pkt.payload_len = len(segment)
                return pkt
            self.stats["reassembled"] += 1
            pkt.frag = "reassembled"
            segment = memoryview(assembled)
        return self._transport(pkt, segment, proto, src=bytes(hdr.src), dst=bytes(hdr.dst))

    # ------------------------------------------------------------------ L4
    def _transport(self, pkt: Packet, segment: memoryview, proto: int, *, src: bytes, dst: bytes) -> Packet:
        pkt.proto = proto
        pkt.proto_name = IP_PROTO_NAMES.get(proto, f"IP-{proto}")

        if proto == IPPROTO_TCP:
            return self._tcp(pkt, segment, src=src, dst=dst)
        if proto == IPPROTO_UDP:
            return self._udp(pkt, segment, src=src, dst=dst)
        if proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
            return self._icmp(pkt, segment, version=6 if proto == IPPROTO_ICMPV6 else 4)

        pkt.payload = segment
        pkt.payload_len = len(segment)
        pkt.layers = (*pkt.layers, pkt.proto_name, "data")
        pkt.info = f"{pkt.proto_name} {pkt.src} → {pkt.dst} ({len(segment)} B)"
        return pkt

    def _tcp(self, pkt: Packet, segment: memoryview, *, src: bytes, dst: bytes) -> Packet:
        try:
            hdr = tcp.parse(segment)
        except ValueError as exc:
            return self._malformed(pkt, f"TCP: {exc}")
        pkt.sport, pkt.dport = hdr.sport, hdr.dport
        pkt.seq, pkt.ack, pkt.win = hdr.seq, hdr.ack, hdr.window
        pkt.tcp_flags = hdr.flags
        pkt.tcp_hdr_len = hdr.header_len
        pkt.mss = hdr.mss or 0
        pkt.wscale = hdr.window_scale if hdr.window_scale is not None else -1
        pkt.opt_sig = hdr.option_signature()
        ts = hdr.timestamps
        if ts:
            pkt.ts_val, pkt.ts_ecr = ts
        pkt.tcp_opts = tuple((kind, len(value)) for kind, value in hdr.options)
        payload = segment[hdr.header_len :]
        pkt.payload = payload
        pkt.payload_len = len(payload)
        pkt.layers = (*pkt.layers, "TCP")
        if self.verify_checksums:
            if not checksum.verify_transport(segment, src=src, dst=dst, proto=IPPROTO_TCP):
                pkt.malformed = (pkt.malformed + "; " if pkt.malformed else "") + "bad TCP checksum"
                self.stats["checksum_errors"] += 1
        flags = tcp_flag_str(hdr.flags)
        pkt.info = (
            f"{hdr.sport} → {hdr.dport} [{flags}] Seq={hdr.seq} Ack={hdr.ack} "
            f"Win={hdr.window} Len={len(payload)}"
        )
        if hdr.mss:
            pkt.info += f" MSS={hdr.mss}"
        if hdr.window_scale is not None:
            pkt.info += f" WS={1 << hdr.window_scale}"
        if hdr.sack_permitted:
            pkt.info += " SACK_PERM"
        return pkt

    def _udp(self, pkt: Packet, segment: memoryview, *, src: bytes, dst: bytes) -> Packet:
        try:
            hdr = udp.parse(segment)
        except ValueError as exc:
            return self._malformed(pkt, f"UDP: {exc}")
        pkt.sport, pkt.dport = hdr.sport, hdr.dport
        payload = udp.payload_view(segment, hdr)
        pkt.payload = payload
        pkt.payload_len = len(payload)
        pkt.layers = (*pkt.layers, "UDP")
        if self.verify_checksums and hdr.checksum:
            if not checksum.verify_transport(
                segment[: max(8, hdr.length)], src=src, dst=dst, proto=IPPROTO_UDP
            ):
                pkt.malformed = (pkt.malformed + "; " if pkt.malformed else "") + "bad UDP checksum"
                self.stats["checksum_errors"] += 1
        pkt.info = f"{hdr.sport} → {hdr.dport} Len={len(payload)}"
        return pkt

    def _icmp(self, pkt: Packet, segment: memoryview, *, version: int) -> Packet:
        try:
            msg = icmp.parse(segment, version=version)
        except ValueError as exc:
            return self._malformed(pkt, f"ICMP: {exc}")
        pkt.payload = segment[4:]
        pkt.payload_len = len(pkt.payload)
        pkt.layers = (*pkt.layers, "ICMPv6" if version == 6 else "ICMP")
        pkt.info = msg.summary()
        return pkt

    # ------------------------------------------------------------------ misc
    def _malformed(self, pkt: Packet, reason: str) -> Packet:
        pkt.malformed = reason
        pkt.info = f"[malformed] {reason}"
        self.stats["malformed"] += 1
        return pkt

    def expire_fragments(self, now: float) -> None:
        self._v4_frag.expire(now)
        self._v6_frag.expire(now)

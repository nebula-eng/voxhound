"""Dissector selection: content sniffing first, port conventions second.

The ordering is the whole point. Ports lie (TLS on 8443, HTTP on 8080, SIP on
5060 *and* 5080, everything on 443), while the first bytes of a stream are hard
to fake and unambiguous for the protocols we care about. Ports are only used to
break ties and to reach protocols with no distinctive preamble (DNS over TCP).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from .base import AppSession

if TYPE_CHECKING:
    from ..flows.table import Flow

TLS_PORTS = {443, 465, 636, 853, 989, 990, 992, 993, 995, 5061, 8443, 8883, 9443}
HTTP_PORTS = {80, 81, 443, 591, 3000, 3128, 5000, 7001, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090}
DNS_PORTS = {53, 5353}
SIP_PORTS = {5060, 5070, 5080}
MQTT_PORTS = {1883, 8883}
RTMP_PORTS = {1935}
QUIC_PORTS = {443, 80, 8080}
QUIC_VERSIONS = {0x00000001, 0x6B3343CF, 0xFF00001D, 0xFF00001C}
RTP_PORT_RANGE = (5004, 65535)


class _Dissector(Protocol):
    name: str

    def feed(self, direction: int, data: bytes) -> None: ...

    def close(self) -> None: ...


def make_stream_dissector(
    flow: Flow, stream: object, first: bytes, direction: int, session: AppSession
) -> _Dissector | None:
    """Pick the best stream dissector for a connection's first payload bytes."""
    head = first[:64]
    port = flow.service_port

    # ---- content sniffing (authoritative)
    if head[:1] == b"\x16" and len(head) >= 3 and head[1] == 0x03:
        from .tls import TlsDissector

        return TlsDissector(session)
    if head.startswith(b"PRI * HTTP/2.0"):
        from .http2 import Http2Dissector

        return Http2Dissector(session)
    if head.startswith((b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI", b"PATC", b"CONN", b"TRAC")):
        from .http1 import Http1Dissector

        return Http1Dissector(session)
    if head.startswith(b"HTTP/1."):
        from .http1 import Http1Dissector

        return Http1Dissector(session)
    if head.startswith(b"SSH-"):
        from .unknown import BannerDissector

        return BannerDissector(session, label="SSH")

    # ---- port conventions
    if port in TLS_PORTS:
        from .tls import TlsDissector

        return TlsDissector(session)
    if port in HTTP_PORTS:
        from .http1 import Http1Dissector

        return Http1Dissector(session)
    if port in DNS_PORTS:
        from .dns import DnsDissector

        return DnsDissector(session, over_tcp=True)
    if port in MQTT_PORTS:
        from .mqtt import MqttDissector

        return MqttDissector(session)
    if port in SIP_PORTS:
        from .sip import SipDissector

        return SipDissector(session)
    if port in RTMP_PORTS:
        from .unknown import BannerDissector, looks_like_rtmp

        if looks_like_rtmp(head):
            return BannerDissector(session, label="RTMP")
        return BannerDissector(session, label="RTMP?")
    if first and _mostly_printable(head):
        from .unknown import BannerDissector

        return BannerDissector(session)
    return None


def make_datagram_dissector(flow: Flow, payload: bytes, session: AppSession) -> _Dissector | None:
    """Pick a dissector for the first datagram of a UDP flow."""
    if not payload:
        return None
    head = payload[:64]
    port = flow.service_port

    from . import stun as stun_mod
    from .dns import DnsDissector
    from .mqtt import MqttDissector
    from .rtp import RtpDissector
    from .sip import SipDissector

    # STUN is unambiguous thanks to its magic cookie.
    if stun_mod.looks_like_stun(head):
        from .stun import StunDissector

        return StunDissector(session)

    if port in DNS_PORTS or _looks_like_dns(payload):
        return DnsDissector(session)

    if port in SIP_PORTS or head.startswith((b"INVITE ", b"REGISTER ", b"SIP/2.0", b"BYE ", b"OPTIONS ")):
        return SipDissector(session)

    if port in MQTT_PORTS:
        return MqttDissector(session)

    # RTP: version 2 and a plausible payload type. Checked before QUIC because
    # both start with a high bit set — getting this order wrong sends every
    # voice call into the QUIC parser.
    if len(payload) >= 12 and payload[0] >> 6 == 2:
        payload_type = payload[1] & 0x7F
        plausible = payload_type < 35 or 96 <= payload_type <= 127
        if plausible and port not in QUIC_PORTS:
            return RtpDissector(session)
        if plausible and port >= 1024 and payload[0] & 0x0F <= 15:
            return RtpDissector(session)

    # QUIC long header with a version we recognise.
    if payload[0] & 0x80 and len(payload) >= 7:
        version = int.from_bytes(payload[1:5], "big")
        if version in QUIC_VERSIONS:
            from .quic import QuicDissector

            return QuicDissector(session)

    if 1000 <= len(payload) <= 1500 and payload[0] >> 6 == 2:
        return RtpDissector(session)
    return None


def _mostly_printable(blob: bytes) -> bool:
    if not blob:
        return False
    printable = sum(1 for b in blob if 0x20 <= b < 0x7F or b in (9, 10, 13))
    return printable / len(blob) > 0.85


def _looks_like_dns(payload: bytes) -> bool:
    """Heuristic: sane header counts and a parsable first question name."""
    if len(payload) < 17 or len(payload) > 4096:
        return False
    flags = int.from_bytes(payload[2:4], "big")
    qdcount = int.from_bytes(payload[4:6], "big")
    ancount = int.from_bytes(payload[6:8], "big")
    if qdcount != 1 or ancount > 64:
        return False
    if not (flags & 0x0100) and not (flags & 0x8000):
        return False
    pos = 12
    labels = 0
    while pos < len(payload) and labels < 16:
        length = payload[pos]
        if length == 0:
            return pos + 5 <= len(payload)
        if length > 63 or pos + 1 + length > len(payload):
            return False
        pos += 1 + length
        labels += 1
    return False

"""A deterministic traffic simulator that produces real protocol bytes.

Why ship a simulator in a forensics tool:

* **Demos without a network.** ``voxhound demo`` gives a full-featured run on a
  laptop with no Npcap, no admin rights and no traffic to capture.
* **Tests that test the real path.** Every fixture is a byte stream, so the
  decoder, reassembler, dissectors and carving all run exactly as they do on a
  wire capture. Mocking objects would prove nothing.
* **Regression baselines.** Seeded, so a report produced today can be diffed
  against one produced next year.

The scenarios cover the interesting corners: TLS with certificates, HTTP/1.1
chunked bodies, h2c with HPACK, WebSocket, a G.711 call, an encrypted QUIC
Initial, DNS with a DGA-shaped name, a port scan and a beaconing pattern.
"""

from __future__ import annotations

import math
import random
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field

from .core.model import RawPacket
from .crypto.aes import gcm_encrypt
from .crypto.hkdf import quic_initial_secrets
from .packets import (
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_SYN,
    dns_query,
    dns_response,
    ethernet,
    http_request,
    http_response,
    ipv4,
    ipv6,
    rtp_packet,
    tcp,
    tcp_options,
    tls_client_hello,
    tls_server_hello,
    udp,
    websocket_frame,
)

CLIENT_MAC = "3c:52:82:11:22:33"
GATEWAY_MAC = "00:1c:42:8f:aa:bb"
BASE_TS = 1_760_000_000.0

CLIENT = "10.10.4.21"
SERVER = "93.184.216.34"
API = "10.10.4.10"
SCAN_TARGET = "10.10.4.9"


# --------------------------------------------------------------------------- helpers
def _varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return struct.pack("!H", value | 0x4000)
    if value < 0x40000000:
        return struct.pack("!I", value | 0x80000000)
    return struct.pack("!Q", value | 0xC000000000000000)


def _fake_certificate(
    cn: str, issuer: str, *, sans: tuple[str, ...] = (), days: int = 400, self_signed: bool = False
) -> bytes:
    """Build a structurally valid DER certificate without any crypto library.

    VoxHound never verifies signatures (it cannot — it is passive), so the
    parser only needs correct TLV nesting. That makes a fixture generator
    possible without pulling in a TLS stack.
    """

    def tlv(tag: int, body: bytes) -> bytes:
        length = len(body)
        if length < 0x80:
            return bytes([tag, length]) + body
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([tag, 0x80 | len(raw)]) + raw + body

    def oid(dotted: str) -> bytes:
        parts = [int(p) for p in dotted.split(".")]
        body = bytes([parts[0] * 40 + parts[1]]) + _base128(parts[2:])
        return tlv(0x06, body)

    def _base128(values: list[int]) -> bytes:
        out = b""
        for value in values:
            remaining = value >> 7
            chunk = [value & 0x7F]
            while remaining:
                chunk.append((remaining & 0x7F) | 0x80)
                remaining >>= 7
            out += bytes(reversed(chunk))
        return out

    def name(common: str, org: str) -> bytes:
        def atv(oid_str: str, value: str) -> bytes:
            return tlv(0x30, oid(oid_str) + tlv(0x0C, value.encode()))

        return tlv(
            0x30,
            tlv(0x31, atv("2.5.4.6", "US"))
            + tlv(0x31, atv("2.5.4.10", org))
            + tlv(0x31, atv("2.5.4.3", common)),
        )

    def utctime(days_from_now: int) -> bytes:
        # 2026-01-01 + N days, encoded as UTCTime
        import datetime as dt

        moment = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(days=days_from_now)
        return tlv(0x17, moment.strftime("%y%m%d%H%M%SZ").encode())

    subject = name(cn, "Example Org")
    issuer_name = subject if self_signed else name(issuer, "Example CA")
    validity = tlv(0x30, utctime(-30) + utctime(days))
    sig_alg = tlv(0x30, oid("1.2.840.113549.1.1.11") + b"\x05\x00")
    spki = tlv(0x30, tlv(0x30, oid("1.2.840.113549.1.1.1") + b"\x05\x00") + tlv(0x03, b"\x00" + b"\x11" * 64))
    extensions = b""
    if sans:
        entries = b"".join(tlv(0x82, san.encode()) for san in sans)
        extensions = tlv(0xA3, tlv(0x30, tlv(0x30, oid("2.5.29.17") + tlv(0x04, tlv(0x30, entries)))))
    tbs = tlv(
        0x30,
        tlv(0xA0, tlv(0x02, b"\x02"))
        + tlv(0x02, b"\x0f\x42\x40")
        + sig_alg
        + issuer_name
        + validity
        + subject
        + spki
        + extensions,
    )
    return tlv(0x30, tbs + sig_alg + tlv(0x03, b"\x00" + b"\x5a" * 128))


def hpack_literal(name: str, value: str, *, index: bool = False) -> bytes:
    """Encode a header field literally (no Huffman) — enough to exercise the decoder."""
    prefix = 0x40 if index else 0x00
    out = bytes([prefix, len(name)]) + name.encode()
    out += bytes([len(value)]) + value.encode()
    return out


@dataclass(slots=True)
class Connection:
    """Sequence-number bookkeeping so reassembly sees a coherent connection."""

    client: str
    server: str
    sport: int
    dport: int
    client_isn: int
    server_isn: int = 0
    client_next: int = field(default=0)
    server_next: int = field(default=0)
    mss: int = 1460

    def __post_init__(self) -> None:
        self.client_next = self.client_isn + 1
        self.server_next = (self.server_isn or (self.client_isn + 0x100000)) + 1


class Timeline:
    """Collects packets and hands them back sorted by time."""

    def __init__(self, seed: int = 7) -> None:
        self.random = random.Random(seed)
        self._frames: list[tuple[float, int, bytes]] = []
        self._order = 0

    def add(self, ts: float, frame: bytes) -> None:
        self._order += 1
        self._frames.append((ts, self._order, frame))

    def packets(self, *, base_ts: float = BASE_TS) -> Iterator[RawPacket]:
        for ts, _order, frame in sorted(self._frames, key=lambda item: (item[0], item[1])):
            yield RawPacket(ts=base_ts + ts, data=frame, caplen=len(frame), wirelen=len(frame))


# --------------------------------------------------------------------------- scenarios
def _tcp_handshake(tl: Timeline, conn: Connection, t0: float) -> None:
    syn = ethernet(
        dst=GATEWAY_MAC,
        src=CLIENT_MAC,
        payload=ipv4(
            conn.client,
            conn.server,
            6,
            tcp(
                conn.sport,
                conn.dport,
                conn.client_isn,
                0,
                TCP_SYN,
                src=conn.client,
                dst=conn.server,
                options=tcp_options(),
            ),
        ),
    )
    synack = ethernet(
        dst=CLIENT_MAC,
        src=GATEWAY_MAC,
        payload=ipv4(
            conn.server,
            conn.client,
            6,
            tcp(
                conn.dport,
                conn.sport,
                conn.server_isn,
                conn.client_isn + 1,
                TCP_SYN | TCP_ACK,
                src=conn.server,
                dst=conn.client,
                options=tcp_options(wscale=7, timestamps=(998877, 123456)),
            ),
        ),
    )
    ack = ethernet(
        dst=GATEWAY_MAC,
        src=CLIENT_MAC,
        payload=ipv4(
            conn.client,
            conn.server,
            6,
            tcp(
                conn.sport,
                conn.dport,
                conn.client_next,
                conn.server_next,
                TCP_ACK,
                src=conn.client,
                dst=conn.server,
            ),
        ),
    )
    tl.add(t0, syn)
    tl.add(t0 + 0.018, synack)
    tl.add(t0 + 0.019, ack)


def _send(
    tl: Timeline, conn: Connection, t0: float, payload: bytes, *, from_client: bool, push: bool = True
) -> float:
    """Split a payload into MSS-sized segments; returns the time after the last one."""
    offset = 0
    step = 0.0
    while offset < len(payload):
        chunk = payload[offset : offset + conn.mss]
        if from_client:
            seq, ack = conn.client_next, conn.server_next
            src, dst, sport, dport = conn.client, conn.server, conn.sport, conn.dport
            conn.client_next += len(chunk)
        else:
            seq, ack = conn.server_next, conn.client_next
            src, dst, sport, dport = conn.server, conn.client, conn.dport, conn.sport
            conn.server_next += len(chunk)
        flags = TCP_ACK | (TCP_PSH if push else 0)
        frame = ethernet(
            dst=GATEWAY_MAC if from_client else CLIENT_MAC,
            src=CLIENT_MAC if from_client else GATEWAY_MAC,
            payload=ipv4(src, dst, 6, tcp(sport, dport, seq, ack, flags, chunk, src=src, dst=dst)),
        )
        tl.add(t0 + step, frame)
        offset += len(chunk)
        step += 0.0007
    return t0 + step


def _close(tl: Timeline, conn: Connection, t0: float) -> None:
    for from_client in (True, False):
        seq = conn.client_next if from_client else conn.server_next
        sport, dport = (conn.sport, conn.dport) if from_client else (conn.dport, conn.sport)
        src, dst = (conn.client, conn.server) if from_client else (conn.server, conn.client)
        frame = ethernet(
            dst=GATEWAY_MAC if from_client else CLIENT_MAC,
            src=CLIENT_MAC if from_client else GATEWAY_MAC,
            payload=ipv4(src, dst, 6, tcp(sport, dport, seq, 0, TCP_FIN | TCP_ACK, src=src, dst=dst)),
        )
        tl.add(t0, frame)
        t0 += 0.001


def scenario_https(tl: Timeline, t0: float) -> float:
    """TLS 1.3 handshake plus encrypted application data, with a real-ish cert chain."""
    conn = Connection(CLIENT, SERVER, 49221, 443, 0x2F1A3C4D, 0x7B2C9D1E)
    _tcp_handshake(tl, conn, t0)
    hello = tls_client_hello("api.example.com")
    t = _send(tl, conn, t0 + 0.020, hello, from_client=True)
    server_hello = tls_server_hello(0x1301)
    cert = _fake_certificate("api.example.com", "Example Root CA", sans=("api.example.com", "*.example.com"))
    body = b"\x00" + (len(cert) + 3).to_bytes(3, "big") + len(cert).to_bytes(3, "big") + cert
    handshake = b"\x0b" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake
    t = _send(tl, conn, t + 0.024, server_hello + record, from_client=False)
    # encrypted application data: random bytes with plausible TLS record framing
    for i in range(3):
        blob = b"\x17\x03\x03" + struct.pack("!H", 512) + tl.random.randbytes(512)
        t = _send(tl, conn, t + 0.010 * (i + 1), blob, from_client=bool(i % 2))
    _close(tl, conn, t + 0.01)
    return t + 0.02


def scenario_http(tl: Timeline, t0: float) -> float:
    """HTTP/1.1 with a chunked PNG body — exercises carving and chunk decoding."""
    conn = Connection(CLIENT, SERVER, 49300, 80, 0x11A2B3C4, 0x55D6E7F8)
    _tcp_handshake(tl, conn, t0)
    request = http_request(
        "GET",
        "/assets/logo.png",
        "cdn.example.com",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0",
            "Accept": "image/png,*/*;q=0.8",
        },
    )
    t = _send(tl, conn, t0 + 0.02, request, from_client=True)
    png = _demo_png()
    chunked = b""
    for offset in range(0, len(png), 300):
        piece = png[offset : offset + 300]
        chunked += f"{len(piece):x}\r\n".encode() + piece + b"\r\n"
    chunked += b"0\r\n\r\n"
    response = http_response(
        200,
        "OK",
        headers={"Content-Type": "image/png", "Server": "nginx/1.27.0", "Transfer-Encoding": "chunked"},
        body=chunked,
    )
    t = _send(tl, conn, t + 0.03, response, from_client=False)
    _close(tl, conn, t + 0.01)
    return t + 0.02


def scenario_http2(tl: Timeline, t0: float) -> float:
    """h2c with HPACK literals: proves the HPACK decoder and CONTINUATION handling."""
    conn = Connection(CLIENT, API, 49310, 8080, 0x2B3C4D5E, 0x6C7D8E9F)
    _tcp_handshake(tl, conn, t0)
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = b"\x00\x00\x00" + b"\x04" + b"\x00" + b"\x00\x00\x00\x00"
    t = _send(tl, conn, t0 + 0.02, preface + settings, from_client=True)
    headers = (
        hpack_literal(":method", "GET")
        + hpack_literal(":scheme", "http")
        + hpack_literal(":authority", "api.example.com")
        + hpack_literal(":path", "/v1/status")
        + hpack_literal("user-agent", "voxhound-demo/1.0")
    )
    frame = len(headers).to_bytes(3, "big") + b"\x01" + b"\x05" + b"\x00\x00\x00\x01" + headers
    t = _send(tl, conn, t + 0.01, frame, from_client=True)
    resp_headers = hpack_literal(":status", "200") + hpack_literal("content-type", "application/json")
    frame = len(resp_headers).to_bytes(3, "big") + b"\x01" + b"\x04" + b"\x00\x00\x00\x01" + resp_headers
    t = _send(tl, conn, t + 0.02, frame, from_client=False)
    payload = b'{"status":"ok","uptime":4211,"voice_sessions":3}'
    data = len(payload).to_bytes(3, "big") + b"\x00" + b"\x01" + b"\x00\x00\x00\x01" + payload
    t = _send(tl, conn, t + 0.005, data, from_client=False)
    _close(tl, conn, t + 0.01)
    return t + 0.02


def scenario_websocket(tl: Timeline, t0: float) -> float:
    """WebSocket upgrade plus voice-ish binary frames."""
    conn = Connection(CLIENT, API, 49320, 8080, 0x3C4D5E6F, 0x7D8E9FA0)
    _tcp_handshake(tl, conn, t0)
    request = http_request(
        "GET",
        "/ws/voice",
        "api.example.com",
        headers={
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
        },
    )
    t = _send(tl, conn, t0 + 0.02, request, from_client=True)
    response = (
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
    )
    t = _send(tl, conn, t + 0.02, response, from_client=False)
    t = _send(
        tl, conn, t + 0.01, websocket_frame(b'{"type":"start","codec":"pcmu","rate":8000}'), from_client=True
    )
    for _ in range(6):
        audio = bytes(tl.random.randrange(0, 256) for _ in range(160))
        t = _send(tl, conn, t + 0.02, websocket_frame(audio, opcode=2), from_client=True)
    _close(tl, conn, t + 0.02)
    return t + 0.03


def _tone_payload(index: int, frequency: float, rate: int, samples: int) -> bytes:
    """One RTP frame of a µ-law encoded sine, with a short fade-in envelope."""
    import struct as _struct

    from .media.wav import ulaw_encode

    pcm = bytearray()
    base = index * samples
    envelope = _speech_envelope(index)
    for n in range(samples):
        value = int(math.sin(2 * math.pi * frequency * (base + n) / rate) * 32000 * envelope)
        pcm += _struct.pack("<h", value)
    return ulaw_encode(bytes(pcm))


def _speech_envelope(index: int) -> float:
    """Three phrases with pauses — a flat tone would render as a featureless block."""
    for start, end in ((2, 30), (38, 66), (74, 94)):
        if start <= index < end:
            rise = min(1.0, (index - start + 1) / 3.0)
            fall = min(1.0, (end - index) / 3.0)
            syllable = 0.55 + 0.45 * abs(math.sin((index - start) * 0.55))
            return 0.66 * min(rise, fall) * syllable
    return 0.0


def _demo_png(width: int = 480, height: int = 160) -> bytes:
    """A real PNG so the media preview can actually decode what was carved.

    Pure stdlib: filter byte per row, zlib-compressed IDAT, CRC per chunk. The
    picture is a dark gradient with one luminous waveform — the project mark.
    """
    import math
    import zlib

    rows = bytearray()
    center = height / 2
    for y in range(height):
        rows.append(0)  # filter: none
        for x in range(width):
            shade = 0.55 * (x / width) + 0.45 * (y / height)
            r = int(9 + 10 * shade)
            g = int(15 + 24 * shade)
            b = int(27 + 46 * shade)
            if 36 <= x < width - 36:
                phase = (x - 36) / (width - 72)
                wave = math.sin(phase * math.pi * 9) * math.exp(-(((phase - 0.5) / 0.42) ** 2))
                distance = abs(y - (center + wave * height * 0.28))
                if distance < 2.2:
                    r, g, b = 108, 168, 255
                elif distance < 5.0:
                    r, g, b = 40, 78, 132
            if 12 <= y < 13 or height - 13 <= y < height - 12:
                r, g, b = 28, 42, 66
            rows += bytes((r, g, b))

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return len(payload).to_bytes(4, "big") + tag + payload + zlib.crc32(tag + payload).to_bytes(4, "big")

    header = width.to_bytes(4, "big") + height.to_bytes(4, "big") + bytes((8, 2, 0, 0, 0))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + chunk(b"IEND", b"")
    )


def scenario_voip(tl: Timeline, t0: float) -> float:
    """A G.711 call between two hosts: 50 packets per second per direction."""
    caller, callee = "10.10.4.21", "10.10.4.40"
    ssrc_a, ssrc_b = 0x1A2B3C4D, 0x5E6F7A8B
    for index in range(100):
        ts_rtp = index * 160
        # Two distinguishable tones (440 Hz / 620 Hz) so the exported WAVs are
        # audibly different and the waveform preview has real structure.
        payload = _tone_payload(index, 440.0, 8000, 160)
        payload_b = _tone_payload(index, 620.0, 8000, 160)
        frame = ethernet(
            dst=GATEWAY_MAC,
            src=CLIENT_MAC,
            payload=ipv4(
                caller,
                callee,
                17,
                udp(
                    40000,
                    40002,
                    rtp_packet(payload, payload_type=0, seq=index, ts=ts_rtp, ssrc=ssrc_a),
                    src=caller,
                    dst=callee,
                ),
            ),
        )
        tl.add(t0 + index * 0.02, frame)
        reverse = ethernet(
            dst=CLIENT_MAC,
            src=GATEWAY_MAC,
            payload=ipv4(
                callee,
                caller,
                17,
                udp(
                    40002,
                    40000,
                    rtp_packet(payload_b, payload_type=0, seq=index, ts=ts_rtp, ssrc=ssrc_b),
                    src=callee,
                    dst=caller,
                ),
            ),
        )
        tl.add(t0 + index * 0.02 + 0.004, reverse)
    return t0 + 2.2


def scenario_dns(tl: Timeline, t0: float) -> float:
    """Normal lookups plus a DGA-shaped name and an oversized label."""
    domains = [
        "api.example.com",
        "cdn.example.com",
        "telemetry.example.net",
        "k7fq2x9z3m1p8r4t6v0y.cn",
        "a" * 54 + ".exfil.example.org",
    ]
    t = t0
    for index, domain in enumerate(domains):
        query = ethernet(
            dst=GATEWAY_MAC,
            src=CLIENT_MAC,
            payload=ipv4(
                CLIENT,
                "10.10.0.2",
                17,
                udp(5353 + index, 53, dns_query(domain, txid=0x1000 + index), src=CLIENT, dst="10.10.0.2"),
            ),
        )
        tl.add(t, query)
        answer = dns_response(domain, [(1, bytes([93, 184, 216, 34]))], txid=0x1000 + index)
        tl.add(
            t + 0.012,
            ethernet(
                dst=CLIENT_MAC,
                src=GATEWAY_MAC,
                payload=ipv4(
                    "10.10.0.2", CLIENT, 17, udp(53, 5353 + index, answer, src="10.10.0.2", dst=CLIENT)
                ),
            ),
        )
        t += 0.06
    return t


def scenario_beacon(tl: Timeline, t0: float, *, interval: float = 3.0, count: int = 7) -> float:
    """Regular DNS callbacks — the beacon detector should fire on this."""
    for index in range(count):
        ts = t0 + index * interval
        tl.add(
            ts,
            ethernet(
                dst=GATEWAY_MAC,
                src=CLIENT_MAC,
                payload=ipv4(
                    CLIENT,
                    "10.10.0.2",
                    17,
                    udp(
                        52000 + index,
                        53,
                        dns_query("beacon.c2.example.net", txid=0x2000 + index),
                        src=CLIENT,
                        dst="10.10.0.2",
                    ),
                ),
            ),
        )
        tl.add(
            ts + 0.01,
            ethernet(
                dst=CLIENT_MAC,
                src=GATEWAY_MAC,
                payload=ipv4(
                    "10.10.0.2",
                    CLIENT,
                    17,
                    udp(
                        53,
                        52000 + index,
                        dns_response(
                            "beacon.c2.example.net", [(1, bytes([198, 51, 100, 7]))], txid=0x2000 + index
                        ),
                        src="10.10.0.2",
                        dst=CLIENT,
                    ),
                ),
            ),
        )
    return t0 + interval * count


def scenario_scan(tl: Timeline, t0: float) -> float:
    """A SYN sweep across 30 ports — the scan heuristic should fire."""
    for index, port in enumerate(
        [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            111,
            135,
            139,
            143,
            443,
            445,
            993,
            995,
            1433,
            3306,
            3389,
            5432,
            5900,
            6379,
            8080,
            8443,
            9200,
            11211,
            27017,
            5000,
            7001,
            8000,
            9000,
        ]
    ):
        frame = ethernet(
            dst=GATEWAY_MAC,
            src=CLIENT_MAC,
            payload=ipv4(
                SCAN_TARGET,
                "10.10.4.21",
                6,
                tcp(
                    51000 + index,
                    port,
                    0x1000 + index,
                    0,
                    TCP_SYN,
                    src=SCAN_TARGET,
                    dst="10.10.4.21",
                    options=tcp_options(mss=1460, wscale=None, sack_perm=False, timestamps=None),
                ),
            ),
        )
        tl.add(t0 + index * 0.01, frame)
    return t0 + 0.4


def scenario_quic(tl: Timeline, t0: float) -> float:
    """A real QUIC Initial packet, AES-GCM encrypted with the RFC 9001 keys.

    This is the strongest test in the suite: if the packet is malformed or the
    key derivation is off by a byte, decryption fails and the SNI never appears.
    """
    dcid = bytes.fromhex("8f5b2c1d4e6a7b90")
    secrets = quic_initial_secrets(dcid, version=1)
    hello = tls_client_hello("quic.example.com", alpn=("h3", "h2"))[5:]  # bare handshake message
    crypto_frame = _varint(0x06) + _varint(0) + _varint(len(hello)) + hello
    padding = b"\x00" * max(0, 1100 - len(crypto_frame))
    payload = crypto_frame + padding

    packet_number = 1
    pn_len = 4
    first = 0xC0 | (pn_len - 1)
    version = struct.pack("!I", 1)
    dcil = bytes([len(dcid)])
    scil = bytes([0])
    token_len = _varint(0)
    length = _varint(len(payload) + pn_len + 16)
    header = (
        bytes([first])
        + version
        + dcil
        + dcid
        + scil
        + token_len
        + length
        + packet_number.to_bytes(pn_len, "big")
    )
    iv = secrets["client_iv"]
    nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + packet_number.to_bytes(8, "big")))
    ciphertext, tag = gcm_encrypt(secrets["client_key"], nonce, payload, aad=header)
    packet = header + ciphertext + tag

    tl.add(
        t0,
        ethernet(
            dst=GATEWAY_MAC,
            src=CLIENT_MAC,
            payload=ipv4(
                CLIENT, "142.250.72.14", 17, udp(51000, 443, packet, src=CLIENT, dst="142.250.72.14")
            ),
        ),
    )
    # A short-header 1-RTT packet: nothing to decrypt, only counters.
    short = bytes([0x41]) + bytes.fromhex("1122334455667788") + b"\xaa" * 200
    tl.add(
        t0 + 0.03,
        ethernet(
            dst=GATEWAY_MAC,
            src=CLIENT_MAC,
            payload=ipv4(
                CLIENT, "142.250.72.14", 17, udp(51000, 443, short, src=CLIENT, dst="142.250.72.14")
            ),
        ),
    )
    return t0 + 0.05


def scenario_ssh(tl: Timeline, t0: float) -> float:
    conn = Connection(CLIENT, "10.10.4.77", 49400, 22, 0x4D5E6F70, 0x0E1F2A3B)
    _tcp_handshake(tl, conn, t0)
    banner = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"
    _send(tl, conn, t0 + 0.03, banner, from_client=False)
    _send(tl, conn, t0 + 0.05, banner, from_client=True)
    return t0 + 0.08


def scenario_ipv6(tl: Timeline, t0: float) -> float:
    """An IPv6 DNS query — exercises the v6 path and the address formatter."""
    inner = udp(5353, 53, dns_query("ipv6.example.com", qtype=28), src="2001:db8::10", dst="2001:db8::53")
    frame = ethernet(
        dst=GATEWAY_MAC,
        src=CLIENT_MAC,
        ethertype=0x86DD,
        payload=ipv6("2001:db8::10", "2001:db8::53", 17, inner),
    )
    tl.add(t0, frame)
    return t0 + 0.02


# --------------------------------------------------------------------------- entry points
def build_timeline(*, duration: float = 20.0, seed: int = 7) -> Timeline:
    tl = Timeline(seed=seed)
    t = 0.05
    t = scenario_dns(tl, t)
    t = scenario_https(tl, t + 0.1)
    t = scenario_http(tl, t + 0.1)
    t = scenario_http2(tl, t + 0.1)
    t = scenario_websocket(tl, t + 0.2)
    t = scenario_ssh(tl, t + 0.1)
    t = scenario_ipv6(tl, t + 0.05)
    t = scenario_quic(tl, t + 0.1)
    t = scenario_voip(tl, t + 0.2)
    t = scenario_scan(tl, t + 0.3)
    t = scenario_beacon(tl, t + 0.2, interval=max(1.5, duration / 7), count=7)
    return tl


def generate_packets(*, duration: float = 20.0, seed: int = 7) -> Iterator[RawPacket]:
    """Yield a ready-to-capture stream of RawPacket objects."""
    return build_timeline(duration=duration, seed=seed).packets()


def write_demo_pcap(path: str, *, duration: float = 20.0, seed: int = 7) -> int:
    from .capture.pcapfile import PcapWriter

    written = 0
    with open(path, "wb") as fh:
        writer = PcapWriter(fh, linktype=1)
        for pkt in generate_packets(duration=duration, seed=seed):
            writer.write(pkt)
            written += 1
    return written


def main() -> int:  # pragma: no cover - developer utility
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "demo.pcap"
    count = write_demo_pcap(target)
    sys.stdout.write(f"wrote {count} packets to {target}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""Packet crafting toolkit.

The engine needs *real bytes* to test against: hand-written fixtures rot, and
mocking a decoder proves nothing. This module builds frames from scratch —
Ethernet, IPv4/IPv6, TCP/UDP, DNS, TLS ClientHello, RTP — with correct
checksums, so tests and the traffic simulator share one source of truth.

It is also genuinely useful on its own: ``python -m voxhound.packets`` prints a
hexdump of any builder's output, which makes it a small Scapy replacement for
the protocols VoxHound understands.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Iterable

ETH_V4 = 0x0800
ETH_V6 = 0x86DD

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def mac(text: str) -> bytes:
    parts = text.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError(f"bad MAC {text!r}")
    return bytes(int(p, 16) for p in parts)


def inet(text: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6 if ":" in text else socket.AF_INET, text)


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for (word,) in struct.iter_unpack("!H", data):
        total += word
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


# --------------------------------------------------------------------------- Ethernet
def ethernet(
    dst: str = "00:11:22:33:44:55",
    src: str = "66:77:88:99:aa:bb",
    ethertype: int = ETH_V4,
    payload: bytes = b"",
    vlan: int | None = None,
) -> bytes:
    head = mac(dst) + mac(src)
    if vlan is not None:
        head += struct.pack("!HH", 0x8100, vlan & 0x0FFF) + struct.pack("!H", ethertype)
    else:
        head += struct.pack("!H", ethertype)
    return head + payload


# --------------------------------------------------------------------------- IPv4
def ipv4(
    src: str,
    dst: str,
    proto: int,
    payload: bytes,
    *,
    ttl: int = 64,
    ident: int = 0x1234,
    flags: int = 0x2,
    frag_offset: int = 0,
    tos: int = 0,
    options: bytes = b"",
) -> bytes:
    ihl = 5 + len(options) // 4
    total_len = ihl * 4 + len(payload)
    header = (
        struct.pack(
            "!BBHHHBBH4s4s",
            (4 << 4) | ihl,
            tos,
            total_len,
            ident,
            (flags << 13) | (frag_offset // 8),
            ttl,
            proto,
            0,
            inet(src),
            inet(dst),
        )
        + options
    )
    checksum = csum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:] + payload


def ipv6(
    src: str,
    dst: str,
    next_header: int,
    payload: bytes,
    *,
    hop_limit: int = 64,
    traffic_class: int = 0,
    flow_label: int = 0,
) -> bytes:
    word0 = (6 << 28) | (traffic_class << 20) | flow_label
    return struct.pack("!IHBB", word0, len(payload), next_header, hop_limit) + inet(src) + inet(dst) + payload


# --------------------------------------------------------------------------- TCP
def tcp_options(
    *,
    mss: int | None = 1460,
    wscale: int | None = 8,
    sack_perm: bool = True,
    timestamps: tuple[int, int] | None = (123456, 0),
    nop_pad: bool = True,
) -> bytes:
    out = b""
    if mss is not None:
        out += struct.pack("!BBH", 2, 4, mss)
    if sack_perm:
        if nop_pad:
            out += b"\x01\x01"
        out += b"\x04\x02"
    if timestamps is not None:
        if nop_pad:
            out += b"\x01\x01"
        out += struct.pack("!BBII", 8, 10, timestamps[0], timestamps[1])
    if wscale is not None:
        out += b"\x01\x03\x03" + bytes([wscale & 0xFF])
    while len(out) % 4:
        out += b"\x00"
    return out


def tcp(
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    *,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    window: int = 64240,
    options: bytes = b"",
    urg: int = 0,
) -> bytes:
    """Build a complete TCP segment with a correct checksum."""
    offset = (5 + len(options) // 4) << 12
    header = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset | flags, window, 0, urg) + options
    pseudo = inet(src) + inet(dst) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    checksum = csum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", checksum) + header[18:] + payload


# --------------------------------------------------------------------------- UDP
def udp(sport: int, dport: int, payload: bytes, *, src: str = "10.0.0.1", dst: str = "10.0.0.2") -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = inet(src) + inet(dst) + struct.pack("!BBH", 0, 17, length)
    checksum = csum(pseudo + header + payload) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, checksum) + payload


# --------------------------------------------------------------------------- DNS
def dns_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        if len(raw) > 63:
            raise ValueError("label too long")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_query(name: str, *, qtype: int = 1, txid: int = 0x1A2B, rd: bool = True) -> bytes:
    flags = 0x0100 if rd else 0
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    return header + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(
    name: str, answers: Iterable[tuple[int, bytes]], *, txid: int = 0x1A2B, ttl: int = 300, qtype: int = 1
) -> bytes:
    answer_list = list(answers)
    header = struct.pack("!HHHHHH", txid, 0x8180, 1, len(answer_list), 0, 0)
    body = dns_name(name) + struct.pack("!HH", qtype, 1)
    for rtype, rdata in answer_list:
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata
    return header + body


# --------------------------------------------------------------------------- TLS
def tls_ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def tls_client_hello(
    sni: str,
    *,
    alpn: tuple[str, ...] = ("h2", "http/1.1"),
    ciphers: Iterable[int] | None = None,
    versions: tuple[int, ...] = (0x0304, 0x0303),
    extension_order: tuple[int, ...] | None = None,
    random: bytes = b"\x7f" * 32,
    session_id: bytes = b"\x11" * 32,
) -> bytes:
    """A realistic ClientHello, GREASE-free, Chrome-shaped by default."""
    cipher_list = (
        list(ciphers)
        if ciphers is not None
        else [
            0x1301,
            0x1302,
            0x1303,
            0xC02B,
            0xC02F,
            0xC02C,
            0xC030,
            0xCCA9,
            0xCCA8,
            0xC013,
            0xC014,
            0x009C,
            0x009D,
            0x002F,
            0x0035,
        ]
    )
    exts: dict[int, bytes] = {
        0x0000: tls_ext(0, struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni.encode()),
        0x0017: tls_ext(0x0017, b""),
        0xFF01: tls_ext(0xFF01, b"\x00"),
        0x000A: tls_ext(0x000A, struct.pack("!H", 6) + struct.pack("!HHH", 0x001D, 0x0017, 0x0018)),
        0x000B: tls_ext(0x000B, b"\x01\x00"),
        0x0023: tls_ext(0x0023, b""),
        0x0010: tls_ext(
            0x0010,
            struct.pack("!H", sum(len(a) + 1 for a in alpn))
            + b"".join(bytes([len(a)]) + a.encode() for a in alpn),
        ),
        0x000D: tls_ext(0x000D, struct.pack("!H", 8) + struct.pack("!HHHH", 0x0403, 0x0804, 0x0401, 0x0503)),
        0x002B: tls_ext(
            0x002B, bytes([len(versions) * 2]) + b"".join(struct.pack("!H", v) for v in versions)
        ),
        0x002D: tls_ext(0x002D, b"\x01\x01"),
        0x0033: tls_ext(0x0033, struct.pack("!H", 36) + struct.pack("!HH", 0x001D, 32) + b"\xab" * 32),
    }
    order = extension_order or tuple(exts)
    blob = b"".join(exts[t] for t in order if t in exts)
    body = (
        b"\x03\x03"
        + random
        + bytes([len(session_id)])
        + session_id
        + struct.pack("!H", len(cipher_list) * 2)
        + b"".join(struct.pack("!H", c) for c in cipher_list)
        + b"\x01\x00"
        + struct.pack("!H", len(blob))
        + blob
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def tls_server_hello(cipher: int = 0x1301, *, version: int = 0x0304, alpn: str | None = "h2") -> bytes:
    body = b"\x03\x03" + b"\x5a" * 32 + b"\x20" + b"\x99" * 32 + struct.pack("!H", cipher) + b"\x00"
    exts = struct.pack("!HH", 0x002B, 2) + struct.pack("!H", version)
    if alpn:
        exts += tls_ext(0x0010, struct.pack("!H", len(alpn) + 1) + bytes([len(alpn)]) + alpn.encode())
    exts += tls_ext(0x0033, struct.pack("!HH", 0x001D, 2) + b"\x00\x00")
    body += struct.pack("!H", len(exts)) + exts
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def http_request(
    method: str = "GET",
    path: str = "/",
    host: str = "example.com",
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for key, value in (headers or {}).items():
        lines.append(f"{key}: {value}")
    if body and "Content-Length" not in (headers or {}):
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_response(
    status: int = 200, reason: str = "OK", *, headers: dict[str, str] | None = None, body: bytes = b""
) -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}"]
    for key, value in (headers or {}).items():
        lines.append(f"{key}: {value}")
    if body and "Content-Length" not in (headers or {}) and "Transfer-Encoding" not in (headers or {}):
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def websocket_frame(payload: bytes, *, opcode: int = 1, fin: bool = True, masked: bool = True) -> bytes:
    head = bytes([(0x80 if fin else 0) | opcode])
    length = len(payload)
    mask_bit = 0x80 if masked else 0
    if length < 126:
        head += bytes([mask_bit | length])
    elif length < 65536:
        head += bytes([mask_bit | 126]) + struct.pack("!H", length)
    else:
        head += bytes([mask_bit | 127]) + struct.pack("!Q", length)
    if not masked:
        return head + payload
    key = b"\x37\xfa\x21\x3d"
    return head + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def rtp_packet(
    payload: bytes,
    *,
    payload_type: int = 0,
    seq: int = 1,
    ts: int = 160,
    ssrc: int = 0x1BADBEEF,
    marker: bool = False,
) -> bytes:
    return (
        struct.pack(
            "!BBHII",
            0x80,
            (0x80 if marker else 0) | (payload_type & 0x7F),
            seq & 0xFFFF,
            ts & 0xFFFFFFFF,
            ssrc & 0xFFFFFFFF,
        )
        + payload
    )


def main() -> int:  # pragma: no cover - tiny developer utility
    import sys

    from .core.util import hexdump

    frame = ethernet(
        payload=ipv4("10.0.0.1", "10.0.0.2", 6, tcp(40000, 443, 1, 0, TCP_SYN, options=tcp_options()))
    )
    sys.stdout.write(hexdump(frame))
    sys.stdout.write(f"\n{len(frame)} bytes\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

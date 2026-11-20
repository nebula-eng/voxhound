"""QUIC: invariant header parsing and *Initial packet decryption* (RFC 9001).

Most tools stop at "this is QUIC". That is unhelpful, because QUIC Initial
packets are encrypted with keys derived from nothing but the Destination
Connection ID — both ends can compute them, and so can a passive observer. This
module does exactly that:

1. parse the invariant long header (version, DCID, SCID, token),
2. derive client/server initial secrets with HKDF-SHA256 and the version salt,
3. AES-128-GCM decrypt the payload, verifying the tag,
4. walk the frames for CRYPTO, reassemble the TLS ClientHello,
5. hand it to the shared ClientHello parser to get SNI, ALPN, versions, JA4Q.

The result is SNI from a QUIC connection without any key material — which is
what actually matters operationally, since QUIC is now the default transport for
HTTP/3 and most mobile apps.

Cost control is explicit: decryption is capped per flow and globally, because a
pure-Python AES-GCM is fast enough for handshakes and far too slow for bulk
traffic. Once the handshake is over, only counters are maintained.
"""

from __future__ import annotations

import struct

from ..core.model import Severity
from ..crypto.aes import gcm_decrypt
from ..crypto.hkdf import quic_initial_secrets
from ..intel import ja4 as ja4mod
from .base import AppSession
from .tls import TlsError, parse_client_hello, parse_server_hello

#: Long-header packet types for QUIC v1 / v2.
PACKET_TYPES_V1 = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
PACKET_TYPES_V2 = {0: "Retry", 1: "Initial", 2: "0-RTT", 3: "Handshake"}

FRAME_PADDING = 0x00
FRAME_PING = 0x01
FRAME_ACK = 0x02
FRAME_ACK_ECN = 0x03
FRAME_CRYPTO = 0x06
FRAME_CONNECTION_CLOSE = 0x1C
FRAME_CONNECTION_CLOSE_APP = 0x1D

MAX_DECRYPTS_PER_FLOW = 6
MAX_DECRYPT_BYTES = 8192


class QuicError(ValueError):
    pass


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(buf):
        raise QuicError("varint past end")
    first = buf[pos]
    length = 1 << (first >> 6)
    if pos + length > len(buf):
        raise QuicError("truncated varint")
    value = first & 0x3F
    for i in range(1, length):
        value = (value << 8) | buf[pos + i]
    return value, pos + length


def _nonce(iv: bytes, packet_number: int) -> bytes:
    pn = packet_number.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(iv, b"\x00\x00\x00\x00" + pn))


class LongHeader:
    __slots__ = (
        "dcid",
        "end",
        "header_len",
        "kind",
        "length",
        "packet_number",
        "packet_number_len",
        "payload_off",
        "raw",
        "scid",
        "type_bits",
        "version",
    )

    def __init__(self) -> None:
        self.raw = b""
        self.kind = ""
        self.type_bits = 0
        self.version = 0
        self.dcid = b""
        self.scid = b""
        self.packet_number = 0
        self.packet_number_len = 0
        self.payload_off = 0
        self.header_len = 0
        self.length = 0
        self.end = 0


def parse_long_header(buf: bytes) -> LongHeader | None:
    """Parse the invariant + type-specific long header; ``None`` if implausible."""
    if len(buf) < 7 or not buf[0] & 0x80:
        return None
    version = struct.unpack_from("!I", buf, 1)[0]
    if version == 0:
        return None  # version negotiation packet
    pos = 5
    dcil = buf[pos]
    pos += 1
    if pos + dcil + 1 > len(buf):
        return None
    dcid = buf[pos : pos + dcil]
    pos += dcil
    scil = buf[pos]
    pos += 1
    if pos + scil > len(buf):
        return None
    scid = buf[pos : pos + scil]
    pos += scil
    header = LongHeader()
    header.version = version
    header.dcid, header.scid = dcid, scid
    header.type_bits = (buf[0] >> 4) & 0x03
    names = PACKET_TYPES_V2 if version == 0x6B3343CF else PACKET_TYPES_V1
    header.kind = names.get(header.type_bits, f"type{header.type_bits}")
    try:
        if header.kind == "Retry":
            header.raw = buf
            return header
        if header.kind == "Initial":
            token_len, pos = read_varint(buf, pos)
            pos += token_len
        length, pos = read_varint(buf, pos)
        pn_len = (buf[0] & 0x03) + 1
        if pos + pn_len > len(buf):
            return None
    except QuicError:
        return None
    packet_number = int.from_bytes(buf[pos : pos + pn_len], "big")
    header.packet_number = packet_number
    header.packet_number_len = pn_len
    header.payload_off = pos + pn_len
    header.header_len = pos + pn_len
    header.length = length
    header.end = min(len(buf), pos + length)
    header.raw = buf
    return header


def walk_frames(payload: bytes) -> list[tuple[int, bytes]]:
    """Return ``(frame_type, body)`` for frames we care about; ignores the rest."""
    frames: list[tuple[int, bytes]] = []
    pos = 0
    while pos < len(payload):
        try:
            frame_type, pos = read_varint(payload, pos)
        except QuicError:
            break
        if frame_type == FRAME_PADDING:
            while pos < len(payload) and payload[pos] == 0:
                pos += 1
            continue
        if frame_type in (FRAME_PING,):
            continue
        if frame_type in (FRAME_ACK, FRAME_ACK_ECN):
            try:
                _largest, pos = read_varint(payload, pos)
                _delay, pos = read_varint(payload, pos)
                range_count, pos = read_varint(payload, pos)
                _first, pos = read_varint(payload, pos)
                for _ in range(range_count):
                    _gap, pos = read_varint(payload, pos)
                    _len, pos = read_varint(payload, pos)
                if frame_type == FRAME_ACK_ECN:
                    for _ in range(3):
                        _v, pos = read_varint(payload, pos)
            except QuicError:
                break
            continue
        if frame_type in (FRAME_CRYPTO,):
            try:
                offset, pos = read_varint(payload, pos)
                length, pos = read_varint(payload, pos)
            except QuicError:
                break
            body = payload[pos : pos + length]
            pos += length
            frames.append((frame_type, offset.to_bytes(8, "big") + body))
            continue
        break  # unknown frame: stop rather than guess
    return frames


class QuicDissector:
    """One UDP flow carrying QUIC."""

    name = "QUIC"

    def __init__(self, session: AppSession) -> None:
        self.s = session
        self.version_names: dict[int, int] = {}
        self.dcid = b""
        self.scid = b""
        self.packets = [0, 0]
        self.initials = 0
        self.decrypted = 0
        self.crypto_buffers: dict[tuple[int, int], bytearray] = {}
        self.client_hello_done = False
        self.server_hello_done = False
        self.sni = ""
        self.alpn = ""
        self.ja4q = ""
        self._secrets: dict[str, bytes] = {}
        self._keys_for_dcid = b""

    # ------------------------------------------------------------------ probing
    def probe(self, payload: bytes) -> bool:
        header = parse_long_header(payload)
        return header is not None and header.kind in ("Initial", "Handshake", "0-RTT", "Retry")

    # ------------------------------------------------------------------ input
    def feed(self, direction: int, data: bytes) -> None:
        self.packets[direction] += 1
        pos = 0
        while pos < len(data):
            chunk = data[pos:]
            header = parse_long_header(chunk)
            if header is None:
                break  # short header (1-RTT) or padding: nothing readable
            self.dcid = header.dcid or self.dcid
            self.scid = header.scid or self.scid
            self.version_names[header.version] = self.version_names.get(header.version, 0) + 1
            if header.kind == "Initial":
                self.initials += 1
                self._handle_initial(direction, chunk, header)
            elif header.kind == "Handshake":
                self.s.tag("quic-handshake")
            elif header.kind == "Retry":
                self.s.emit("quic", "QUIC Retry (address validation)", severity=Severity.INFO)
            if header.end <= pos:
                break
            pos += header.end

    def _handle_initial(self, direction: int, buf: bytes, header: LongHeader) -> None:
        if self._keys_for_dcid != header.dcid or not self._secrets:
            self._secrets = quic_initial_secrets(header.dcid, version=header.version) or {}
            self._keys_for_dcid = header.dcid
            if not self._secrets:
                if self.initials <= 1:
                    self.s.emit(
                        "quic",
                        f"QUIC {ja4mod.quic_version_name(header.version)} "
                        f"dcid={header.dcid.hex()[:16]} (no initial keys for this version)",
                        severity=Severity.INFO,
                    )
                return
            self.s.emit(
                "quic",
                f"QUIC {ja4mod.quic_version_name(header.version)} handshake "
                f"dcid={header.dcid.hex()[:16]} scid={header.scid.hex()[:16]}",
                version=ja4mod.quic_version_name(header.version),
                dcid=header.dcid.hex(),
                scid=header.scid.hex(),
            )
            flow = self.flow
            if flow is not None:
                flow.notes["quic_dcid"] = header.dcid.hex()
            self.s.tag("quic")
        if self.decrypted >= MAX_DECRYPTS_PER_FLOW:
            return
        ciphertext_end = header.end
        if ciphertext_end - header.payload_off < 17:
            return
        ciphertext = buf[header.payload_off : ciphertext_end - 16]
        tag = buf[ciphertext_end - 16 : ciphertext_end]
        if len(ciphertext) > MAX_DECRYPT_BYTES:
            return
        aad = buf[: header.header_len]
        plaintext = self._try_decrypt(header, aad, ciphertext, tag)
        if plaintext is None:
            return
        self.decrypted += 1
        for frame_type, body in walk_frames(plaintext):
            if frame_type == FRAME_CRYPTO:
                offset = int.from_bytes(body[:8], "big")
                self._handle_crypto(direction, offset, body[8:])

    def _try_decrypt(self, header: LongHeader, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes | None:
        for side in ("client", "server"):
            key = self._secrets.get(f"{side}_key")
            iv = self._secrets.get(f"{side}_iv")
            if not key or not iv:
                continue
            try:
                return gcm_decrypt(key, _nonce(iv, header.packet_number), ciphertext, tag, aad)
            except ValueError:
                continue
        return None

    def _handle_crypto(self, direction: int, offset: int, data: bytes) -> None:
        key = (direction, offset)
        buffer = self.crypto_buffers.setdefault(key, bytearray())
        buffer += data
        blob = bytes(buffer)
        # RFC 9001 says CRYPTO carries bare handshake messages, but some stacks
        # (and our own fixture) hand us a TLS record header first. Skip it so a
        # harmless framing difference does not lose the SNI.
        if len(blob) >= 5 and blob[0] == 0x16:
            record_len = int.from_bytes(blob[3:5], "big")
            blob = blob[5 : 5 + record_len] if len(blob) >= 5 + record_len else blob[5:]
        while len(blob) >= 4:
            msg_type = blob[0]
            length = int.from_bytes(blob[1:4], "big")
            if len(blob) < 4 + length:
                return
            body = blob[4 : 4 + length]
            if msg_type == 1 and not self.client_hello_done:
                self._on_client_hello(body)
            elif msg_type == 2 and not self.server_hello_done:
                self._on_server_hello(body)
            blob = blob[4 + length :]
        self.crypto_buffers[key] = bytearray(blob)

    def _on_client_hello(self, body: bytes) -> None:
        self.client_hello_done = True
        try:
            hello = parse_client_hello(body)
        except (TlsError, struct.error, IndexError) as exc:
            self.s.emit("quic", f"unparsable QUIC ClientHello: {exc}", severity=Severity.LOW)
            return
        self.sni = hello.sni
        self.alpn = hello.alpn[0] if hello.alpn else ""
        self.ja4q = ja4mod.compute_ja4(
            ciphers=hello.ciphers,
            extensions=hello.extensions,
            sig_algs=hello.sig_algs,
            versions=hello.versions,
            legacy_version=hello.legacy_version,
            alpn=hello.alpn,
            sni=hello.sni or None,
            protocol="q",
        )
        flow = self.flow
        if flow is not None:
            flow.sni = hello.sni or flow.sni
            flow.alpn = self.alpn
            flow.ja4 = self.ja4q
            flow.tls_version = hello.version_name
        self.s.emit(
            "quic",
            f"QUIC ClientHello {hello.sni or '(no SNI)'} {hello.version_name} {self.alpn or '-'} JA4 {self.ja4q}",
            sni=hello.sni,
            alpn=hello.alpn,
            ja4=self.ja4q,
            version=hello.version_name,
            decrypted=True,
        )
        if hello.ech:
            self.s.tag("ech")

    def _on_server_hello(self, body: bytes) -> None:
        self.server_hello_done = True
        try:
            hello = parse_server_hello(body)
        except (TlsError, struct.error, IndexError):
            return
        if hello.alpn:
            self.alpn = hello.alpn
        self.s.emit(
            "quic",
            f"QUIC ServerHello cipher=0x{hello.cipher:04x} alpn={hello.alpn or '-'}",
            cipher=hello.cipher,
            alpn=hello.alpn,
        )

    def close(self) -> None:
        if self.initials:
            self.s.emit(
                "quic",
                f"QUIC flow closed · {sum(self.packets)} datagrams · {self.initials} Initial · "
                f"{self.decrypted} decrypted{' · SNI ' + self.sni if self.sni else ''}",
                datagrams=sum(self.packets),
                initials=self.initials,
                decrypted=self.decrypted,
                sni=self.sni,
            )

    @property
    def flow(self) -> object:
        return self.s.flow

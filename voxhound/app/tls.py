"""TLS handshake analysis: SNI, ALPN, versions, ciphers, certificates, JA3/JA4/JA4S.

Everything here works on the cleartext handshake only — no decryption, no
certificate pinning bypass, no MITM. That is a deliberate scope decision: the
tool answers "who is this client talking to, with which stack, claiming which
identity" from passive bytes, which is exactly what you need in an incident and
what keeps the tool usable inside networks where TLS interception is forbidden.

Records and handshake messages are handled separately because a single
handshake message may span multiple records and a single record may carry
several messages — a detail naive parsers get wrong on real captures.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ..core.model import Severity
from ..intel import ja4 as ja4mod
from ..intel.x509 import CertificateInfo, parse_certificate
from .base import AppSession, StreamDissector

CONTENT_CHANGE_CIPHER_SPEC = 20
CONTENT_ALERT = 21
CONTENT_HANDSHAKE = 22
CONTENT_APPLICATION_DATA = 23

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_NEW_SESSION_TICKET = 4
HS_ENCRYPTED_EXTENSIONS = 8
HS_CERTIFICATE = 11
HS_CERTIFICATE_REQUEST = 13
HS_SERVER_KEY_EXCHANGE = 12
HS_FINISHED = 20

ALERT_NAMES = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    22: "record_overflow",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    109: "missing_extension",
    110: "unsupported_extension",
    112: "unrecognized_name",
    116: "certificate_required",
    120: "no_application_protocol",
}

CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE_ECDSA_AES128_GCM_SHA256",
    0xC02C: "ECDHE_ECDSA_AES256_GCM_SHA384",
    0xC02F: "ECDHE_RSA_AES128_GCM_SHA256",
    0xC030: "ECDHE_RSA_AES256_GCM_SHA384",
    0xCCA8: "ECDHE_RSA_CHACHA20_POLY1305",
    0xCCA9: "ECDHE_ECDSA_CHACHA20_POLY1305",
    0x009C: "RSA_AES128_GCM_SHA256",
    0x009D: "RSA_AES256_GCM_SHA384",
    0x002F: "RSA_AES128_SHA",
    0x0035: "RSA_AES256_SHA",
    0xC013: "ECDHE_RSA_AES128_SHA",
    0xC014: "ECDHE_RSA_AES256_SHA",
    0xC009: "ECDHE_ECDSA_AES128_SHA",
    0x000A: "RSA_3DES_EDE_SHA",
}

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_COMPRESS_CERTIFICATE = 0x001B
EXT_SESSION_TICKET = 0x0023
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_PSK_KEY_EXCHANGE_MODES = 0x002D
EXT_KEY_SHARE = 0x0033
EXT_PRE_SHARED_KEY = 0x0029
EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D

TLS_VERSIONS = {0x0304: "TLS1.3", 0x0303: "TLS1.2", 0x0302: "TLS1.1", 0x0301: "TLS1.0", 0x0300: "SSL3.0"}


class TlsError(ValueError):
    pass


@dataclass(slots=True)
class ClientHello:
    legacy_version: int
    ciphers: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    versions: list[int] = field(default_factory=list)
    sig_algs: list[int] = field(default_factory=list)
    curves: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)
    sni: str = ""
    session_id_len: int = 0
    ech: bool = False
    psk: bool = False

    @property
    def version_name(self) -> str:
        best = max(self.versions) if self.versions else self.legacy_version
        return TLS_VERSIONS.get(best, f"0x{best:04x}")


def parse_client_hello(body: bytes) -> ClientHello:
    if len(body) < 34:
        raise TlsError("short ClientHello")
    legacy_version = struct.unpack_from("!H", body, 0)[0]
    pos = 34  # version + random
    sid_len = body[pos]
    pos += 1 + sid_len
    if pos + 2 > len(body):
        raise TlsError("truncated cipher list")
    cipher_len = struct.unpack_from("!H", body, pos)[0]
    pos += 2
    if pos + cipher_len > len(body):
        raise TlsError("cipher list overruns hello")
    ciphers = list(struct.unpack_from(f"!{cipher_len // 2}H", body, pos))
    pos += cipher_len
    comp_len = body[pos] if pos < len(body) else 0
    pos += 1 + comp_len
    hello = ClientHello(legacy_version=legacy_version, ciphers=ciphers, session_id_len=sid_len)
    if pos + 2 > len(body):
        return hello
    ext_total = struct.unpack_from("!H", body, pos)[0]
    pos += 2
    end = min(len(body), pos + ext_total)
    while pos + 4 <= end:
        ext_type, ext_len = struct.unpack_from("!HH", body, pos)
        pos += 4
        data = body[pos : pos + ext_len]
        pos += ext_len
        hello.extensions.append(ext_type)
        if ext_type == EXT_SERVER_NAME:
            hello.sni = _parse_sni(data)
        elif ext_type == EXT_ALPN:
            hello.alpn = _parse_alpn(data)
        elif ext_type == EXT_SUPPORTED_VERSIONS:
            hello.versions = _parse_u16_list(data, 1)
        elif ext_type == EXT_SIGNATURE_ALGORITHMS:
            hello.sig_algs = _parse_u16_list(data, 2)
        elif ext_type == EXT_SUPPORTED_GROUPS:
            hello.curves = _parse_u16_list(data, 2)
        elif ext_type == EXT_EC_POINT_FORMATS:
            hello.point_formats = list(data[1 : 1 + data[0]]) if data else []
        elif ext_type == EXT_ENCRYPTED_CLIENT_HELLO:
            hello.ech = True
        elif ext_type == EXT_PRE_SHARED_KEY:
            hello.psk = True
    return hello


def _parse_sni(data: bytes) -> str:
    if len(data) < 5:
        return ""
    name_len = struct.unpack_from("!H", data, 3)[0]
    raw = data[5 : 5 + name_len]
    try:
        return raw.decode("idna")
    except UnicodeError:
        return raw.decode("utf-8", "replace")


def _parse_alpn(data: bytes) -> list[str]:
    out: list[str] = []
    if len(data) < 2:
        return out
    total = struct.unpack_from("!H", data, 0)[0]
    pos = 2
    end = min(len(data), 2 + total)
    while pos < end:
        length = data[pos]
        pos += 1
        out.append(data[pos : pos + length].decode("ascii", "replace"))
        pos += length
    return out


def _parse_u16_list(data: bytes, prefix: int) -> list[int]:
    total = data[0] if data else 0
    raw = data[prefix : prefix + total]
    return [raw[i] << 8 | raw[i + 1] for i in range(0, len(raw) - 1, 2)]


@dataclass(slots=True)
class ServerHello:
    version: int
    cipher: int
    alpn: str = ""
    extensions: list[int] = field(default_factory=list)
    session_id_len: int = 0


def parse_server_hello(body: bytes) -> ServerHello:
    if len(body) < 38:
        raise TlsError("short ServerHello")
    version = struct.unpack_from("!H", body, 0)[0]
    pos = 34
    sid_len = body[pos]
    pos += 1 + sid_len
    cipher = struct.unpack_from("!H", body, pos)[0]
    pos += 3  # cipher + compression
    hello = ServerHello(version=version, cipher=cipher, session_id_len=sid_len)
    if pos + 2 <= len(body):
        ext_total = struct.unpack_from("!H", body, pos)[0]
        pos += 2
        end = min(len(body), pos + ext_total)
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack_from("!HH", body, pos)
            pos += 4
            data = body[pos : pos + ext_len]
            pos += ext_len
            hello.extensions.append(ext_type)
            if ext_type == EXT_SUPPORTED_VERSIONS and len(data) >= 2:
                hello.version = struct.unpack_from("!H", data, 0)[0]
            elif ext_type == EXT_ALPN and len(data) >= 3:
                hello.alpn = data[3 : 3 + data[2]].decode("ascii", "replace")
    return hello


def split_certificates(body: bytes, *, tls13: bool) -> list[bytes]:
    """Extract DER blobs from a Certificate message, both TLS 1.2 and 1.3 shapes."""
    pos = 0
    if tls13:
        if not body:
            return []
        ctx_len = body[0]
        pos = 1 + ctx_len
        if pos + 3 > len(body):
            return []
        list_len = int.from_bytes(body[pos : pos + 3], "big")
        pos += 3
        return _walk_cert_list(body[pos : pos + list_len] if list_len else body[pos:])
    if len(body) < 3:
        return []
    list_len = int.from_bytes(body[0:3], "big")
    return _walk_cert_list(body[3 : 3 + list_len] if list_len else body[3:])


def _walk_cert_list(blob: bytes) -> list[bytes]:
    out: list[bytes] = []
    pos = 0
    while pos + 3 <= len(blob):
        length = int.from_bytes(blob[pos : pos + 3], "big")
        pos += 3
        if length <= 0 or pos + length > len(blob):
            break
        out.append(blob[pos : pos + length])
        pos += length
    return out


class TlsDissector(StreamDissector):
    """Stateful TLS record/handshake parser for one TCP connection."""

    name = "TLS"

    MAX_BUFFER = 1 << 20

    def __init__(self, session: AppSession) -> None:
        super().__init__(session)
        self._records: list[bytearray] = [bytearray(), bytearray()]
        self._hs: list[bytearray] = [bytearray(), bytearray()]
        self.client_hello: ClientHello | None = None
        self.server_hello: ServerHello | None = None
        self.certificates: list[CertificateInfo] = []
        self.record_count = [0, 0]
        self.app_bytes = [0, 0]
        self.alert_count = 0
        self.ja4 = ""
        self.ja4s = ""
        self.version = ""
        self.alpn = ""
        self.sni = ""

    # ------------------------------------------------------------------ input
    def feed(self, direction: int, data: bytes) -> None:
        buf = self._records[direction]
        buf += data
        while len(buf) >= 5:
            content_type = buf[0]
            length = struct.unpack_from("!H", buf, 3)[0]
            if length > 18432:  # larger than any legal TLS record
                self.s.emit("tls", "oversized TLS record — stream desynchronised", severity=Severity.LOW)
                buf.clear()
                return
            if len(buf) < 5 + length:
                return
            record = bytes(buf[5 : 5 + length])
            record_version = struct.unpack_from("!H", buf, 1)[0]
            del buf[: 5 + length]
            self.record_count[direction] += 1
            self._handle_record(direction, content_type, record_version, record)
        if len(buf) > self.MAX_BUFFER:
            buf.clear()
            self.s.tag("tls-desync")

    def _handle_record(self, direction: int, content_type: int, version: int, body: bytes) -> None:
        if content_type == CONTENT_HANDSHAKE:
            hs = self._hs[direction]
            hs += body
            self._drain_handshake(direction, version)
        elif content_type == CONTENT_APPLICATION_DATA:
            self.app_bytes[direction] += len(body)
            if len(self.app_bytes) > 1:
                pass
            self.s.note("tls_ciphertext_bytes", list(self.app_bytes))
        elif content_type == CONTENT_ALERT and len(body) >= 2:
            self.alert_count += 1
            level, description = body[0], body[1]
            name = ALERT_NAMES.get(description, f"alert {description}")
            severity = Severity.MEDIUM if description in (40, 42, 48, 112, 120) else Severity.INFO
            self.s.emit(
                "tls",
                f"TLS alert {name} (level {level})",
                severity=severity,
                description=description,
                level=level,
            )
            if description == 112:
                self.s.tag("sni-rejected")

    def _drain_handshake(self, direction: int, record_version: int) -> None:
        hs = self._hs[direction]
        while len(hs) >= 4:
            msg_type = hs[0]
            length = int.from_bytes(hs[1:4], "big")
            if length > 8 << 20:
                hs.clear()
                return
            if len(hs) < 4 + length:
                return
            body = bytes(hs[4 : 4 + length])
            del hs[: 4 + length]
            self._handle_handshake(direction, msg_type, body, record_version)

    def _handle_handshake(self, direction: int, msg_type: int, body: bytes, record_version: int) -> None:
        if msg_type == HS_CLIENT_HELLO:
            try:
                hello = parse_client_hello(body)
            except (TlsError, struct.error, IndexError) as exc:
                self.s.emit("tls", f"unparsable ClientHello: {exc}", severity=Severity.LOW)
                return
            self.client_hello = hello
            self.sni = hello.sni
            self.version = hello.version_name
            self.alpn = hello.alpn[0] if hello.alpn else ""
            self.ja4 = ja4mod.compute_ja4(
                ciphers=hello.ciphers,
                extensions=hello.extensions,
                sig_algs=hello.sig_algs,
                versions=hello.versions,
                legacy_version=hello.legacy_version,
                alpn=hello.alpn,
                sni=hello.sni or None,
            )
            ja3 = ja4mod.compute_ja3(
                ciphers=hello.ciphers,
                extensions=hello.extensions,
                curves=hello.curves,
                point_formats=hello.point_formats,
                legacy_version=hello.legacy_version,
            )
            flow = self.flow
            if flow is not None:
                flow.sni = hello.sni or flow.sni
                flow.alpn = self.alpn
                flow.ja4 = self.ja4
                flow.ja3 = ja3
                flow.tls_version = self.version
            self.s.emit(
                "tls",
                f"ClientHello {hello.sni or '(no SNI)'} {self.version} {self.alpn or '-'} JA4 {self.ja4}",
                sni=hello.sni,
                version=self.version,
                alpn=hello.alpn,
                ja4=self.ja4,
                ja3=ja3,
                ciphers=len(hello.ciphers),
                extensions=len(hello.extensions),
                ech=hello.ech,
                psk=hello.psk,
            )
            if hello.ech:
                self.s.tag("ech")
            if not hello.sni:
                self.s.tag("no-sni")
            if hello.psk:
                self.s.tag("session-resumption")
        elif msg_type == HS_SERVER_HELLO:
            try:
                hello = parse_server_hello(body)
            except (TlsError, struct.error, IndexError):
                return
            self.server_hello = hello
            self.ja4s = ja4mod.compute_ja4s(
                cipher=hello.cipher,
                extensions=hello.extensions,
                alpn=[hello.alpn] if hello.alpn else [],
                version=hello.version,
            )
            if hello.alpn:
                self.alpn = hello.alpn
            if hello.version in TLS_VERSIONS:
                self.version = TLS_VERSIONS[hello.version]
            cipher_name = CIPHER_SUITES.get(hello.cipher, f"0x{hello.cipher:04x}")
            flow = self.flow
            if flow is not None:
                flow.ja4s = self.ja4s
                flow.cipher = cipher_name
            self.s.emit(
                "tls",
                f"ServerHello {self.version} {cipher_name} JA4S {self.ja4s}",
                version=self.version,
                cipher=cipher_name,
                ja4s=self.ja4s,
                alpn=self.alpn,
            )
        elif msg_type == HS_CERTIFICATE:
            self._handle_certificate(body)
        elif msg_type == HS_FINISHED:
            self.s.emit("tls", "handshake complete", version=self.version, sni=self.sni, alpn=self.alpn)
        elif msg_type == HS_ENCRYPTED_EXTENSIONS:
            pass  # encrypted in TLS 1.3; no cleartext to read

    def _handle_certificate(self, body: bytes) -> None:
        tls13 = bool(self.server_hello and self.server_hello.version == 0x0304) or self.version == "TLS1.3"
        ders = [der for der in split_certificates(body, tls13=tls13) if der]
        if not ders and not tls13:
            ders = [der for der in split_certificates(body, tls13=True) if der]
        for der in ders[:8]:
            try:
                info = parse_certificate(der)
            except Exception:  # noqa: BLE001 - DER is hostile input
                continue
            self.certificates.append(info)
        if not self.certificates:
            self.s.emit("tls", "certificate message without parsable certificates", severity=Severity.LOW)
            return
        leaf = self.certificates[0]
        flow = self.flow
        if flow is not None:
            flow.cert_cn = leaf.common_name
            flow.cert_issuer = leaf.issuer
        self.s.emit(
            "tls",
            f"certificate {leaf.summary() or leaf.subject} issuer={leaf.issuer}",
            subject=leaf.subject,
            issuer=leaf.issuer,
            common_name=leaf.common_name,
            organization=leaf.organization,
            sans=leaf.sans[:16],
            not_before=leaf.not_before.isoformat() if leaf.not_before else "",
            not_after=leaf.not_after.isoformat() if leaf.not_after else "",
            chain_length=len(self.certificates),
            self_signed=leaf.self_signed,
        )
        if leaf.self_signed:
            self.s.tag("self-signed-cert")
            self.s.emit(
                "tls",
                f"self-signed certificate for {leaf.common_name or '?'}",
                severity=Severity.MEDIUM,
                issuer=leaf.issuer,
            )
        if leaf.expired():
            self.s.tag("expired-cert")
            self.s.emit("tls", f"expired certificate (notAfter {leaf.not_after})", severity=Severity.MEDIUM)
        days = leaf.days_valid()
        if days is not None and 0 <= days <= 7:
            self.s.tag("cert-expiring")
        if self.sni and not leaf.matches_host(self.sni):
            self.s.tag("cert-hostname-mismatch")
            self.s.emit(
                "tls",
                f"certificate name mismatch: SNI {self.sni} vs CN {leaf.common_name or '?'}",
                severity=Severity.HIGH,
                sni=self.sni,
                common_name=leaf.common_name,
                sans=leaf.sans[:8],
            )

    # ------------------------------------------------------------------ close
    def close(self) -> None:
        super().close()
        total = self.app_bytes[0] + self.app_bytes[1]
        if total:
            self.s.emit(
                "tls",
                f"TLS session {self.sni or '(no sni)'} closed · {total / 1024:.0f} KiB encrypted "
                f"({self.app_bytes[0] / 1024:.0f} up / {self.app_bytes[1] / 1024:.0f} down)",
                bytes_up=self.app_bytes[0],
                bytes_down=self.app_bytes[1],
                records=self.record_count[0] + self.record_count[1],
                alerts=self.alert_count,
            )
        self._records[0].clear()
        self._records[1].clear()

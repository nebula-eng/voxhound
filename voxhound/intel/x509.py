"""A minimal DER/X.509 reader — enough to say *who* a certificate claims to be.

Pulling cert metadata out of a passive capture is one of the highest-value
things an analyst can do on encrypted traffic: SNI tells you the host, and the
certificate tells you the organisation behind it, the validity window, whether
it is self-signed, and whether it matches the name that was requested.

No external crypto library, no signature verification (we are passive — we
cannot validate a chain we cannot see), just structural parsing of the fields
that matter.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

OID_CN = "2.5.4.3"
OID_C = "2.5.4.6"
OID_L = "2.5.4.7"
OID_ST = "2.5.4.8"
OID_O = "2.5.4.10"
OID_OU = "2.5.4.11"
OID_SAN = "2.5.29.17"
OID_BASIC_CONSTRAINTS = "2.5.29.19"

_ATTR_NAMES = {
    OID_CN: "CN",
    OID_C: "C",
    OID_L: "L",
    OID_ST: "ST",
    OID_O: "O",
    OID_OU: "OU",
}

SIG_ALGS = {
    "1.2.840.113549.1.1.11": "sha256WithRSA",
    "1.2.840.113549.1.1.12": "sha384WithRSA",
    "1.2.840.113549.1.1.13": "sha512WithRSA",
    "1.2.840.113549.1.1.5": "sha1WithRSA",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}


class DerError(ValueError):
    pass


@dataclass(slots=True)
class Tlv:
    tag: int
    start: int
    end: int  # exclusive, of content


def read_tlv(data: bytes, pos: int) -> Tlv:
    if pos + 2 > len(data):
        raise DerError("truncated TLV header")
    tag = data[pos]
    length = data[pos + 1]
    cursor = pos + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or cursor + count > len(data):
            raise DerError("unsupported length encoding")
        length = int.from_bytes(data[cursor : cursor + count], "big")
        cursor += count
    end = cursor + length
    if end > len(data):
        raise DerError("TLV length runs past buffer")
    return Tlv(tag=tag, start=cursor, end=end)


def children(data: bytes, tlv: Tlv) -> list[Tlv]:
    out: list[Tlv] = []
    pos = tlv.start
    while pos < tlv.end:
        child = read_tlv(data, pos)
        out.append(child)
        pos = child.end
    return out


def decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _decode_string(data: bytes, tlv: Tlv) -> str:
    raw = data[tlv.start : tlv.end]
    if tlv.tag == 0x1E:  # BMPString
        return raw.decode("utf-16-be", "replace")
    if tlv.tag == 0x1C:  # UniversalString
        return raw.decode("utf-32-be", "replace")
    return raw.decode("utf-8", "replace")


def parse_name(data: bytes, tlv: Tlv) -> str:
    """RDNSequence → ``CN=x, O=y, C=z``."""
    parts: list[str] = []
    for rdn in children(data, tlv):
        for atv in children(data, rdn):
            pair = children(data, atv)
            if len(pair) < 2:
                continue
            oid = decode_oid(data[pair[0].start : pair[0].end])
            name = _ATTR_NAMES.get(oid)
            if name:
                parts.append(f"{name}={_decode_string(data, pair[1])}")
    return ", ".join(parts)


def _parse_time(data: bytes, tlv: Tlv) -> dt.datetime | None:
    text = data[tlv.start : tlv.end].decode("ascii", "replace").rstrip("Z")
    try:
        if tlv.tag == 0x17 and len(text) >= 12:  # UTCTime
            year = int(text[0:2])
            year += 2000 if year < 50 else 1900
            return dt.datetime(
                year,
                int(text[2:4]),
                int(text[4:6]),
                int(text[6:8]),
                int(text[8:10]),
                int(text[10:12]),
                tzinfo=dt.timezone.utc,
            )
        if tlv.tag == 0x18 and len(text) >= 14:  # GeneralizedTime
            return dt.datetime(
                int(text[0:4]),
                int(text[4:6]),
                int(text[6:8]),
                int(text[8:10]),
                int(text[10:12]),
                int(text[12:14]),
                tzinfo=dt.timezone.utc,
            )
    except ValueError:
        return None
    return None


@dataclass(slots=True)
class CertificateInfo:
    subject: str = ""
    issuer: str = ""
    common_name: str = ""
    organization: str = ""
    serial: str = ""
    signature_algorithm: str = ""
    not_before: dt.datetime | None = None
    not_after: dt.datetime | None = None
    sans: list[str] = field(default_factory=list)
    is_ca: bool = False
    ip_address_sans: list[str] = field(default_factory=list)

    @property
    def self_signed(self) -> bool:
        return bool(self.subject) and self.subject == self.issuer

    def days_valid(self, now: dt.datetime | None = None) -> int | None:
        if not self.not_after:
            return None
        now = now or dt.datetime.now(dt.timezone.utc)
        return (self.not_after - now).days

    def expired(self, now: dt.datetime | None = None) -> bool:
        days = self.days_valid(now)
        return days is not None and days < 0

    def matches_host(self, host: str) -> bool:
        """RFC 6125-ish match against CN and dNSName SANs, wildcards included."""
        host = host.lower().rstrip(".")
        candidates = [cn.lower() for cn in ([self.common_name] if self.common_name else [])]
        candidates += [san.lower() for san in self.sans]
        for candidate in candidates:
            if candidate == host:
                return True
            if candidate.startswith("*.") and host.count(".") >= candidate.count("."):
                if host.split(".", 1)[1] == candidate[2:]:
                    return True
        return False

    def summary(self) -> str:
        bits = []
        if self.common_name:
            bits.append(f"CN={self.common_name}")
        if self.organization:
            bits.append(f"O={self.organization}")
        if self.signature_algorithm:
            bits.append(self.signature_algorithm)
        return " · ".join(bits)


def parse_certificate(der: bytes) -> CertificateInfo:
    """Parse a DER certificate; raises :class:`DerError` on anything structural."""
    cert = read_tlv(der, 0)
    cert_parts = children(der, cert)
    if not cert_parts:
        raise DerError("empty certificate")
    tbs = cert_parts[0]
    info = CertificateInfo()
    tbs_parts = children(der, tbs)
    index = 0
    if tbs_parts and tbs_parts[0].tag == 0xA0:  # [0] EXPLICIT version
        index = 1
    if index >= len(tbs_parts):
        raise DerError("certificate missing serial")
    serial = der[tbs_parts[index].start : tbs_parts[index].end]
    info.serial = serial.hex().lstrip("0") or "0"
    index += 1
    if index < len(tbs_parts) and tbs_parts[index].tag == 0x30:  # signature AlgorithmIdentifier
        alg_parts = children(der, tbs_parts[index])
        if alg_parts:
            info.signature_algorithm = SIG_ALGS.get(
                decode_oid(der[alg_parts[0].start : alg_parts[0].end]), info.signature_algorithm
            )
        index += 1
    if index < len(tbs_parts):
        info.issuer = parse_name(der, tbs_parts[index])
        index += 1
    if index < len(tbs_parts) and tbs_parts[index].tag == 0x30:  # Validity
        validity = children(der, tbs_parts[index])
        if len(validity) >= 2:
            info.not_before = _parse_time(der, validity[0])
            info.not_after = _parse_time(der, validity[1])
        index += 1
    if index < len(tbs_parts):
        info.subject = parse_name(der, tbs_parts[index])
        index += 1
    for attr in info.subject.split(", "):
        key, _, value = attr.partition("=")
        if key == "CN" and not info.common_name:
            info.common_name = value
        elif key == "O" and not info.organization:
            info.organization = value
    # Extensions live in the [3] EXPLICIT wrapper at the tail of TBSCertificate.
    for part in tbs_parts[index:]:
        if part.tag != 0xA3:
            continue
        for ext_seq in children(der, part):
            for ext in children(der, ext_seq):
                fields = children(der, ext)
                if len(fields) < 2:
                    continue
                oid = decode_oid(der[fields[0].start : fields[0].end])
                value_tlv = fields[-1]
                if oid == OID_SAN:
                    _parse_san(der, value_tlv, info)
                elif oid == OID_BASIC_CONSTRAINTS:
                    info.is_ca = b"\x01\x01\xff" in der[value_tlv.start : value_tlv.end]
    return info


def _parse_san(der: bytes, tlv: Tlv, info: CertificateInfo) -> None:
    try:
        seq = read_tlv(der, tlv.start)
        for entry in children(der, seq):
            raw = der[entry.start : entry.end]
            if entry.tag == 0x82:  # dNSName
                info.sans.append(raw.decode("ascii", "replace"))
            elif entry.tag == 0x87 and len(raw) == 4:  # iPAddress
                info.ip_address_sans.append(".".join(str(b) for b in raw))
            elif entry.tag == 0x87 and len(raw) == 16:
                info.ip_address_sans.append(
                    ":".join(f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2))
                )
    except DerError:
        return


def parse_certificates(blob: bytes) -> list[CertificateInfo]:
    """Best-effort: parse consecutive DER certificates until the buffer ends."""
    out: list[CertificateInfo] = []
    pos = 0
    while pos < len(blob) - 4:
        try:
            tlv = read_tlv(blob, pos)
        except DerError:
            break
        if tlv.tag != 0x30:
            break
        try:
            out.append(parse_certificate(blob[pos : tlv.end]))
        except (DerError, IndexError, ValueError):
            break
        pos = tlv.end
    return out

"""DNS message parsing: queries, responses, resource records, DGA hints.

DNS is the highest-signal protocol in any capture. It is unencrypted in most
networks, it names every destination, and its failure modes are loud. This
parser is deliberately complete: names compression, EDNS0, and the record types
that matter for triage (A/AAAA/CNAME/MX/TXT/NS/SOA/SRV/HTTPS/CAA/PTR).

It also does something Wireshark does not: it scores every queried label for
DGA-like shape (entropy, digit ratio, consonant runs) and flags algorithmic
domains, which is what makes the beacon detector possible.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ..core.model import Severity
from ..core.util import shannon_entropy
from .base import AppSession

TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    52: "TLSA",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY",
    257: "CAA",
}

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class DnsError(ValueError):
    pass


@dataclass(slots=True)
class Question:
    name: str
    qtype: int
    qclass: int


@dataclass(slots=True)
class Record:
    name: str
    rtype: int
    ttl: int
    data: object

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.rtype, f"TYPE{self.rtype}")


@dataclass(slots=True)
class DnsMessage:
    txid: int
    flags: int
    questions: list[Question] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authority: list[Record] = field(default_factory=list)
    additional: list[Record] = field(default_factory=list)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0x0F

    @property
    def rcode(self) -> int:
        return self.flags & 0x0F

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def recursion_desired(self) -> bool:
        return bool(self.flags & 0x0100)

    @property
    def authoritative(self) -> bool:
        return bool(self.flags & 0x0400)

    def first_name(self) -> str:
        return self.questions[0].name if self.questions else ""


def read_name(buf: bytes | memoryview, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) domain name; returns ``(name, next_offset)``."""
    labels: list[str] = []
    pos = offset
    jumped = False
    end_offset = offset
    seen: set[int] = set()
    for _ in range(128):  # loop guard for pointer cycles
        if pos >= len(buf):
            raise DnsError("name runs past end of message")
        length = buf[pos]
        if length == 0:
            pos += 1
            if not jumped:
                end_offset = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                raise DnsError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                end_offset = pos + 2
                jumped = True
            if pointer in seen:
                raise DnsError("compression pointer loop")
            seen.add(pointer)
            pos = pointer
            continue
        pos += 1
        raw = bytes(buf[pos : pos + length])
        if len(raw) < length:
            raise DnsError("truncated label")
        try:
            labels.append(raw.decode("idna") if _is_ascii(raw) else raw.decode("utf-8", "replace"))
        except UnicodeError:
            labels.append(raw.decode("utf-8", "replace"))
        pos += length
    else:
        raise DnsError("name too long")

    name = ".".join(labels)
    if name and not name.endswith("."):
        name += "."
    return name, (end_offset if jumped else pos)


def _is_ascii(raw: bytes) -> bool:
    return all(b < 0x80 or b >= 0xC0 for b in raw)


def parse(buf: bytes | memoryview) -> DnsMessage:
    if len(buf) < 12:
        raise DnsError("short DNS header")
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", buf, 0)
    msg = DnsMessage(txid=txid, flags=flags)
    offset = 12
    for _ in range(qdcount):
        name, offset = read_name(buf, offset)
        if offset + 4 > len(buf):
            raise DnsError("truncated question")
        qtype, qclass = struct.unpack_from("!HH", buf, offset)
        offset += 4
        msg.questions.append(Question(name=name, qtype=qtype, qclass=qclass))
    for count, target in ((ancount, msg.answers), (nscount, msg.authority), (arcount, msg.additional)):
        for _ in range(count):
            record, offset = _read_record(buf, offset)
            target.append(record)
    return msg


def _read_record(buf: bytes | memoryview, offset: int) -> tuple[Record, int]:
    name, offset = read_name(buf, offset)
    if offset + 10 > len(buf):
        raise DnsError("truncated resource record")
    rtype, _rclass, ttl, rdlength = struct.unpack_from("!HHIH", buf, offset)
    offset += 10
    rdata_start = offset
    rdata = memoryview(buf)[offset : offset + rdlength]
    if len(rdata) < rdlength:
        raise DnsError("truncated rdata")
    offset += rdlength
    data: object
    if rtype == 1 and rdlength == 4:
        data = ".".join(str(b) for b in rdata)
    elif rtype == 28 and rdlength == 16:
        data = _format_ipv6(bytes(rdata))
    elif rtype in (2, 5, 12):
        data, _ = read_name(buf, rdata_start)
    elif rtype == 15:
        preference = struct.unpack_from("!H", rdata, 0)[0]
        target, _ = read_name(buf, rdata_start + 2)
        data = (preference, target)
    elif rtype == 16:
        chunks = []
        pos = 0
        while pos < len(rdata):
            length = rdata[pos]
            pos += 1
            chunks.append(bytes(rdata[pos : pos + length]).decode("utf-8", "replace"))
            pos += length
        data = "".join(chunks)
    elif rtype == 33:
        priority, weight, port = struct.unpack_from("!HHH", rdata, 0)
        target, _ = read_name(buf, rdata_start + 6)
        data = (priority, weight, port, target)
    elif rtype in (64, 65):
        priority = struct.unpack_from("!H", rdata, 0)[0]
        target, _ = read_name(buf, rdata_start + 2)
        data = (priority, target)
    elif rtype == 6:
        mname, pos = read_name(buf, rdata_start)
        rname, pos = read_name(buf, pos)
        serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", buf, pos)
        data = {
            "mname": mname,
            "rname": rname,
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum": minimum,
        }
    else:
        data = bytes(rdata)
    return Record(name=name, rtype=rtype, ttl=ttl, data=data), offset


def _format_ipv6(raw: bytes) -> str:
    groups = [int.from_bytes(raw[i : i + 2], "big") for i in range(0, 16, 2)]
    return ":".join(f"{g:x}" for g in groups)


# --------------------------------------------------------------------------- DGA scoring
def dga_score(name: str) -> float:
    """0..1 heuristic: how much a domain label looks machine-generated.

    Signals (weighted): high per-character entropy, low vowel ratio, long
    consonant runs, digits mixed into letters. Deliberately simple and
    explainable — an analyst must be able to argue with the verdict.
    """
    label = name.split(".", 1)[0].strip().lower()
    if len(label) < 8:
        return 0.0
    entropy = shannon_entropy(label.encode())
    digits = sum(c.isdigit() for c in label) / len(label)
    vowels = sum(c in "aeiou" for c in label) / len(label)
    longest_run = _longest_consonant_run(label)
    score = 0.0
    score += min(1.0, max(0.0, (entropy - 2.8) / 1.8)) * 0.45
    score += min(1.0, digits / 0.25) * 0.2
    score += min(1.0, max(0.0, (0.22 - vowels) / 0.22)) * 0.2
    score += min(1.0, longest_run / 7) * 0.15
    return round(min(1.0, score), 3)


def _longest_consonant_run(text: str) -> int:
    best = current = 0
    for ch in text:
        if ch.isalpha() and ch not in "aeiou":
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


# --------------------------------------------------------------------------- dissector
class DnsDissector:
    """Handles DNS over UDP (one datagram per message) and TCP (length-prefixed)."""

    name = "DNS"

    def __init__(self, session: AppSession, *, over_tcp: bool = False) -> None:
        self.s = session
        self.over_tcp = over_tcp
        self._buffer = bytearray()
        self.s.app_name = self.name

    # ------------------------------------------------------------------ input
    def feed(self, direction: int, data: bytes) -> None:
        if not self.over_tcp:
            self._handle(direction, data)
            return
        self._buffer += data
        while len(self._buffer) >= 2:
            length = struct.unpack_from("!H", self._buffer, 0)[0]
            if len(self._buffer) < 2 + length:
                return
            message = bytes(self._buffer[2 : 2 + length])
            del self._buffer[: 2 + length]
            self._handle(direction, message)

    def _handle(self, direction: int, data: bytes) -> None:
        try:
            msg = parse(data)
        except DnsError as exc:
            self.s.emit("dns", f"malformed DNS message: {exc}", severity=Severity.LOW)
            return
        name = msg.first_name()
        qtype = TYPE_NAMES.get(msg.questions[0].qtype, "?") if msg.questions else "?"
        if msg.is_response:
            answers = [r for r in msg.answers if r.rtype in (1, 28, 5)]
            ips = [str(r.data) for r in answers if r.rtype in (1, 28)]
            rcodes = RCODE_NAMES.get(msg.rcode, str(msg.rcode))
            self.s.emit(
                "dns",
                f"DNS response {name} {qtype} {rcodes}" + (f" → {', '.join(ips[:4])}" if ips else ""),
                ttl=msg.answers[0].ttl if msg.answers else 0,
                answers=ips,
                rcode=rcodes,
                txid=msg.txid,
            )
            self.s.note("dns_answers", ips[:8])
            if msg.rcode == 3:
                self.s.tag("nxdomain")
        else:
            self.s.emit("dns", f"DNS query {name} {qtype}", question=name, qtype=qtype, txid=msg.txid)
            flow = self.s.flow
            if flow is not None and hasattr(flow, "dns_names") and name not in flow.dns_names:
                if len(flow.dns_names) < 64:
                    flow.dns_names.append(name)
            score = dga_score(name)
            if score >= 0.6:
                self.s.tag("dga?")
                self.s.emit(
                    "dns",
                    f"suspicious algorithmic domain {name} (score {score:.2f})",
                    severity=Severity.MEDIUM,
                    dga_score=score,
                )
                self.s.note("dga_score", score)
        if msg.truncated:
            self.s.tag("dns-truncated")

    def close(self) -> None:
        self._buffer.clear()

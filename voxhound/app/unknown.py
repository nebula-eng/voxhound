"""Fallback dissectors for protocols we identify but do not fully decode.

Coverage beats depth here: knowing that a stream is ``SSH-2.0-OpenSSH_9.6`` or
an RTMP publish session is often all an analyst needs to triage it, and it costs
one module instead of six.
"""

from __future__ import annotations

import re

from ..core.model import Severity
from .base import AppSession, StreamDissector

_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{6,}")

BANNER_HINTS: tuple[tuple[bytes, str], ...] = (
    (b"SSH-", "SSH"),
    (b"220 ", "SMTP/FTP"),
    (b"+OK", "POP3"),
    (b"* OK", "IMAP"),
    (b"-ERR", "POP3"),
    (b"HTTP/1.", "HTTP"),
    (b"+PONG", "Redis"),
    (b"-NOAUTH", "Redis"),
    (b"$", "Redis"),
    (b"RTMP", "RTMP"),
    (b"AMF", "RTMP/AMF"),
    (b"RFB ", "VNC"),
    (b"MySQL", "MySQL"),
    (b"PostgreSQL", "PostgreSQL"),
    (b"STOMP", "STOMP"),
    (b"XMPP", "XMPP"),
)


class BannerDissector(StreamDissector):
    """Emit the first meaningful banner/string a stream utters, then go quiet."""

    name = "Banner"

    def __init__(self, session: AppSession, *, label: str = "") -> None:
        super().__init__(session)
        self._seen = 0
        self._bytes = bytearray()
        self.label = label

    def feed(self, direction: int, data: bytes) -> None:
        if self._seen >= 2:
            return
        self._bytes += data[:4096]
        if len(self._bytes) < 8 and len(data) < 8:
            return
        banner = self._extract(bytes(self._bytes))
        if banner:
            self._seen += 1
            protocol = self._classify(banner)
            self.s.emit(
                "banner",
                f"{protocol or self.label or 'banner'}: {banner[:120]}",
                banner=banner[:512],
                protocol=protocol,
                severity=Severity.INFO,
            )
            if protocol and protocol != self.s.app_name:
                self.s.app_name = protocol
                flow = self.flow
                if flow is not None and not flow.app:
                    flow.app = protocol
            if protocol == "SSH":
                self.s.tag("ssh")
            self._bytes.clear()
        elif len(self._bytes) > 4096:
            self._bytes.clear()
            self._seen = 2

    def _extract(self, blob: bytes) -> str:
        match = _PRINTABLE_RUN.search(blob)
        if match:
            return match.group().decode("ascii", "replace")
        # binary protocol that still carries a version string (RTMP, MySQL handshake)
        for hint, _name in BANNER_HINTS:
            index = blob.find(hint)
            if index >= 0:
                tail = blob[index : index + 64]
                match = _PRINTABLE_RUN.search(tail)
                if match:
                    return match.group().decode("ascii", "replace")
        return ""

    def _classify(self, banner: str) -> str:
        for hint, name in BANNER_HINTS:
            if (
                banner.startswith(hint.decode("ascii", "replace"))
                or hint.decode("ascii", "replace") in banner[:24]
            ):
                return name
        if banner.startswith("SSH-"):
            return "SSH"
        if banner.startswith("220 ") or "SMTP" in banner or "FTP" in banner:
            return "SMTP/FTP"
        return ""


def looks_like_rtmp(blob: bytes) -> bool:
    """RTMP handshake: C0 is the version byte (3), followed by 1536 random bytes."""
    return len(blob) >= 1537 and blob[0] in (3, 6) and blob[1:5] != b"\x00\x00\x00\x00"

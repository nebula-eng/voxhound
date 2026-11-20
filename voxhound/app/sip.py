"""SIP signalling: call legs, identities and SDP media endpoints.

When SIP is present it tells you what RTP alone cannot: who called whom, the
Call-ID that ties legs together, and which UDP ports carry the audio. VoxHound
uses that to annotate RTP flows rather than to pretend it is a full B2BUA.
"""

from __future__ import annotations

import re

from ..core.model import Severity
from .base import AppSession, StreamDissector

_METHODS = (
    "INVITE",
    "ACK",
    "BYE",
    "CANCEL",
    "REGISTER",
    "OPTIONS",
    "SUBSCRIBE",
    "NOTIFY",
    "REFER",
    "INFO",
    "PRACK",
    "UPDATE",
    "MESSAGE",
    "PUBLISH",
)

_STATUS_RE = re.compile(r"^SIP/2\.0 (\d{3}) (.*)$")
_HEADER_RE = re.compile(r"^([A-Za-z-]+):\s*(.*)$")


class SipDissector(StreamDissector):
    name = "SIP"

    def __init__(self, session: AppSession) -> None:
        super().__init__(session)
        self._buffers = [bytearray(), bytearray()]
        self.call_id = ""
        self.from_uri = ""
        self.to_uri = ""
        self.media_ports: list[int] = []
        self.messages = 0

    def feed(self, direction: int, data: bytes) -> None:
        buf = self._buffers[direction]
        buf += data
        while True:
            head_end = buf.find(b"\r\n\r\n")
            if head_end < 0:
                if len(buf) > 64 << 10:
                    buf.clear()
                return
            head = bytes(buf[:head_end])
            content_length = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    try:
                        content_length = int(line.split(b":", 1)[1].strip())
                    except ValueError:
                        content_length = 0
            total = head_end + 4 + content_length
            if len(buf) < total:
                return
            body = bytes(buf[head_end + 4 : total])
            del buf[:total]
            self._handle(
                direction, head.decode("iso-8859-1", "replace"), body.decode("iso-8859-1", "replace")
            )

    def _handle(self, direction: int, head: str, body: str) -> None:
        lines = head.split("\r\n")
        if not lines:
            return
        first = lines[0]
        status_match = _STATUS_RE.match(first)
        if status_match:
            self.messages += 1
            code = int(status_match.group(1))
            self.s.emit(
                "sip",
                f"{code} {status_match.group(2)}",
                status=code,
                severity=Severity.LOW if code >= 400 else Severity.INFO,
            )
            return
        parts = first.split(" ")
        if not parts or parts[0] not in _METHODS:
            return
        self.messages += 1
        method = parts[0]
        uri = parts[1] if len(parts) > 1 else ""
        headers: dict[str, str] = {}
        for line in lines[1:]:
            match = _HEADER_RE.match(line)
            if match:
                headers[match.group(1).lower()] = match.group(2).strip()
        self.call_id = headers.get("call-id", self.call_id)
        self.from_uri = headers.get("from", self.from_uri)
        self.to_uri = headers.get("to", self.to_uri)
        if method == "INVITE" and body:
            self._parse_sdp(body)
        flow = self.flow
        if flow is not None:
            if self.call_id and "call_id" not in flow.notes:
                flow.notes["call_id"] = self.call_id
            if headers.get("user-agent") and headers["user-agent"] not in flow.user_agents:
                flow.user_agents.append(headers["user-agent"])
        self.s.emit(
            "sip",
            f"{method} {uri}",
            method=method,
            uri=uri,
            call_id=self.call_id,
            from_uri=self.from_uri,
            to_uri=self.to_uri,
            user_agent=headers.get("user-agent", ""),
        )
        if method == "BYE":
            self.s.tag("call-ended")

    def _parse_sdp(self, body: str) -> None:
        codecs: list[str] = []
        connection = ""
        for line in body.split("\r\n"):
            if line.startswith("m=audio"):
                parts = line.split()
                if len(parts) > 1 and parts[1].isdigit():
                    self.media_ports.append(int(parts[1]))
            elif line.startswith("c="):
                connection = line[2:].strip()
            elif line.startswith("a=rtpmap:"):
                codecs.append(line.split(":", 1)[1].strip())
        if self.media_ports or codecs:
            self.s.note("sdp_media", {"ports": self.media_ports, "codecs": codecs[:8]})
            self.s.emit(
                "sip",
                f"SDP offers media ports {self.media_ports} codecs {', '.join(codecs[:4]) or '-'}",
                ports=self.media_ports,
                codecs=codecs,
                connection=connection,
            )
            self.s.tag("voip-signalling")

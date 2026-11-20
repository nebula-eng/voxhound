"""HTTP/1.x request/response parsing with chunked decoding and body carving.

Design points
-------------
* One dissector instance can hold several *pipelined* exchanges: HTTP/1.1 allows
  a client to send request 2 before response 1 arrives, so parsers that assume
  strict alternation break on real traffic.
* Bodies are streamed into a bounded buffer (8 MiB). Anything larger is counted
  and marked truncated rather than silently eating memory — captures of video
  downloads are common and would otherwise OOM the tool.
* Interesting bodies are carved as artifacts with a magic-byte type sniff, not
  a content-type guess: servers lie, magic bytes do not.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.model import Severity
from ..core.util import printable_ratio
from .base import AppSession, StreamDissector

MAX_BODY = 8 << 20
MAX_HEADER = 64 << 10

MAGIC_SNIFFS: tuple[tuple[bytes, str, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png", "png"),
    (b"\xff\xd8\xff", "image/jpeg", "jpg"),
    (b"GIF87a", "image/gif", "gif"),
    (b"GIF89a", "image/gif", "gif"),
    (b"RIFF", "audio/wav", "wav"),
    (b"OggS", "audio/ogg", "ogg"),
    (b"ID3", "audio/mpeg", "mp3"),
    (b"\xff\xfb", "audio/mpeg", "mp3"),
    (b"\xff\xf1", "audio/aac", "aac"),
    (b"\xff\xf9", "audio/aac", "aac"),
    (b"#!AMR", "audio/amr", "amr"),
    (b"#!SILK_V3", "audio/silk", "silk"),
    (b"%PDF-", "application/pdf", "pdf"),
    (b"PK\x03\x04", "application/zip", "zip"),
    (b"\x1f\x8b", "application/gzip", "gz"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7z"),
    (b"Rar!\x1a\x07", "application/vnd.rar", "rar"),
    (b"\x00\x00\x00\x18ftyp", "video/mp4", "mp4"),
    (b"\x1aE\xdf\xa3", "video/webm", "webm"),
    (b"FLV\x01", "video/x-flv", "flv"),
    (b"{\\rtf", "application/rtf", "rtf"),
    (b"SQLite format 3\x00", "application/vnd.sqlite3", "sqlite"),
    (b"\x7fELF", "application/x-elf", "elf"),
    (b"MZ", "application/x-dosexec", "exe"),
)

TEXT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/x-www-form-urlencoded",
    "image/svg",
)


def sniff_magic(data: bytes) -> tuple[str, str] | None:
    for magic, mime, ext in MAGIC_SNIFFS:
        if data.startswith(magic):
            return mime, ext
    return None


@dataclass(slots=True)
class HttpMessage:
    is_request: bool
    method: str = ""
    target: str = ""
    version: str = "HTTP/1.1"
    status: int = 0
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytearray = field(default_factory=bytearray)
    body_size: int = 0
    truncated: bool = False
    chunked_remaining: int = 0
    complete: bool = False
    state: str = "headers"

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class Http1Dissector(StreamDissector):
    """One TCP connection carrying HTTP/1.x (possibly TLS-decrypted later on)."""

    name = "HTTP"

    def __init__(self, session: AppSession) -> None:
        super().__init__(session)
        self._buffers = [bytearray(), bytearray()]
        self._pending: list[HttpMessage] = []  # request/response queue, pipelining-safe
        self._current: list[HttpMessage | None] = [None, None]
        self._cookies: list[str] = []
        self._ws_upgraded = False

    # ------------------------------------------------------------------ input
    def feed(self, direction: int, data: bytes) -> None:
        if self._ws_upgraded:
            return
        buf = self._buffers[direction]
        buf += data
        while True:
            msg = self._current[direction]
            if msg is None:
                msg = HttpMessage(is_request=self._looks_like_request(bytes(buf[:16])))
                self._current[direction] = msg
            if msg.state == "headers":
                end = buf.find(b"\r\n\r\n")
                if end < 0:
                    if len(buf) > MAX_HEADER:
                        self.s.emit("http", "oversized HTTP header block", severity=Severity.LOW)
                        self._buffers[direction].clear()
                        self._current[direction] = None
                    return
                head = bytes(buf[:end])
                del buf[: end + 4]
                self._parse_head(msg, head)
                self._on_head(direction, msg)
                if msg.complete:
                    self._finish(direction, msg)
                    self._current[direction] = None
                    continue
                msg.state = "body"
            if msg.state == "body":
                if not self._consume_body(msg, buf):
                    return
                self._finish(direction, msg)
                self._current[direction] = None
                if not buf:
                    return
            else:  # pragma: no cover - defensive
                self._current[direction] = None
                return

    def _looks_like_request(self, head: bytes) -> bool:
        return any(
            head.startswith(m) for m in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"OPTI", b"PATC")
        )

    def _parse_head(self, msg: HttpMessage, head: bytes) -> None:
        text = head.decode("iso-8859-1", "replace")
        lines = text.split("\r\n")
        first = lines[0] if lines else ""
        if msg.is_request:
            parts = first.split(" ")
            if len(parts) >= 2:
                msg.method = parts[0]
                msg.target = parts[1]
                msg.version = parts[2] if len(parts) > 2 else "HTTP/1.1"
        else:
            parts = first.split(" ", 2)
            if len(parts) >= 2:
                msg.version = parts[0]
                msg.status = int(parts[1]) if parts[1].isdigit() else 0
                msg.reason = parts[2] if len(parts) > 2 else ""
        for line in lines[1:]:
            name, _, value = line.partition(":")
            if name:
                msg.headers[name.strip().lower()] = value.strip()
        transfer = msg.header("transfer-encoding").lower()
        length = msg.header("content-length")
        if "chunked" in transfer:
            msg.state = "chunked"
            msg.chunked_remaining = -1
        elif length.isdigit():
            msg.state = "body"
            msg.chunked_remaining = int(length)
        else:
            msg.state = "body"
            msg.chunked_remaining = 0 if msg.is_request else -1
        if msg.is_request and msg.chunked_remaining == 0:
            msg.complete = True
        if not msg.is_request and msg.chunked_remaining == 0 and msg.status not in (204, 304):
            msg.complete = msg.body_size == 0

    # ------------------------------------------------------------------ bodies
    def _consume_body(self, msg: HttpMessage, buf: bytearray) -> bool:
        """Return True when the message is complete."""
        # Chunked framing must win over the fixed-length path: after a chunk is
        # split across segments ``chunked_remaining`` holds the *chunk* size, and
        # treating it as Content-Length would silently drop the next size line.
        if msg.header("transfer-encoding", "").lower().find("chunked") >= 0:
            return self._consume_chunked(msg, buf)
        if msg.chunked_remaining == 0:
            msg.complete = True
            return True
        if msg.chunked_remaining > 0:
            take = min(msg.chunked_remaining, len(buf))
            self._append_body(msg, bytes(buf[:take]))
            del buf[:take]
            msg.chunked_remaining -= take
            if msg.chunked_remaining:
                return False
            msg.complete = True
            return True
        # read-until-close response
        self._append_body(msg, bytes(buf))
        buf.clear()
        return msg.is_request  # responses ending at close are finished in close()

    def _consume_chunked(self, msg: HttpMessage, buf: bytearray) -> bool:
        while True:
            if msg.chunked_remaining < 0:
                line_end = buf.find(b"\r\n")
                if line_end < 0:
                    return False
                size_field = bytes(buf[:line_end]).split(b";")[0].strip()
                del buf[: line_end + 2]
                try:
                    msg.chunked_remaining = int(size_field, 16)
                except ValueError:
                    msg.truncated = True
                    msg.complete = True
                    return True
                if msg.chunked_remaining == 0:
                    trailer_end = buf.find(b"\r\n")
                    if trailer_end >= 0:
                        del buf[: trailer_end + 2]
                    msg.complete = True
                    return True
            if len(buf) < msg.chunked_remaining + 2:
                return False
            self._append_body(msg, bytes(buf[: msg.chunked_remaining]))
            del buf[: msg.chunked_remaining + 2]
            msg.chunked_remaining = -1

    def _append_body(self, msg: HttpMessage, chunk: bytes) -> None:
        msg.body_size += len(chunk)
        room = MAX_BODY - len(msg.body)
        if room > 0:
            msg.body += chunk[:room]
        if len(chunk) > room:
            msg.truncated = True

    # ------------------------------------------------------------------ events
    def _on_head(self, direction: int, msg: HttpMessage) -> None:
        host = msg.header("host") or msg.header(":authority")
        if msg.is_request:
            flow = self.flow
            if flow is not None and host and host not in flow.http_hosts and len(flow.http_hosts) < 32:
                flow.http_hosts.append(host)
            ua = msg.header("user-agent")
            if ua and flow is not None and ua not in flow.user_agents and len(flow.user_agents) < 8:
                flow.user_agents.append(ua)
            cookie = msg.header("cookie")
            if cookie:
                self._cookies.append(cookie[:256])
            self.s.emit(
                "http",
                f"{msg.method} {host}{msg.target}",
                method=msg.method,
                host=host,
                target=msg.target,
                ua=ua,
                bytes=msg.body_size or int(msg.header("content-length") or 0),
            )
            upgrade = msg.header("upgrade").lower()
            if upgrade == "websocket" and msg.header("sec-websocket-key"):
                self.s.tag("websocket")
                self.s.emit("http", f"WebSocket upgrade to {msg.target}", host=host, target=msg.target)
        else:
            self.s.emit(
                "http",
                f"{msg.status} {msg.reason} {msg.header('content-type')} {msg.body_size} B",
                status=msg.status,
                reason=msg.reason,
                content_type=msg.header("content-type"),
                length=msg.body_size,
                server=msg.header("server"),
            )
            if msg.status >= 500:
                self.s.tag("http-5xx")
            elif msg.status >= 400:
                self.s.tag("http-4xx")
            location = msg.header("location")
            if location and msg.status in (301, 302, 303, 307, 308):
                self.s.emit("http", f"redirect → {location}", severity=Severity.INFO, location=location)

    def _finish(self, direction: int, msg: HttpMessage) -> None:
        if msg.body:
            self._carve_body(msg)
        if not msg.is_request and msg.status >= 200:
            self._check_ws_upgrade(msg)

    def _check_ws_upgrade(self, msg: HttpMessage) -> None:
        if msg.header("upgrade").lower() == "websocket" or msg.status == 101:
            if self._ws_upgraded:
                return
            self._ws_upgraded = True
            from .websocket import WebSocketDissector

            ws = WebSocketDissector(self.s)
            if self.s.stream is not None:
                self.s.stream.app = ws
            self.s.app_name = "WebSocket"
            self.s.emit("ws", "WebSocket session established", status=msg.status)

    def _carve_body(self, msg: HttpMessage) -> None:
        body = bytes(msg.body)
        if len(body) < 128:
            return
        sniffed = sniff_magic(body)
        content_type = msg.header("content-type").split(";")[0].strip().lower()
        is_text = any(content_type.startswith(t) for t in TEXT_TYPES)
        if sniffed is None and is_text and printable_ratio(body[:512]) > 0.85:
            if len(body) > 1024:
                self.s.artifact(
                    "text/plain",
                    f"http-body-{msg.status or msg.method}.txt",
                    body,
                    source="http",
                    content_type=content_type,
                )
            return
        if sniffed is None:
            if len(body) < 2048 or printable_ratio(body[:256]) > 0.7:
                return
            sniffed = ("application/octet-stream", "bin")
        mime, ext = sniffed
        name = msg.target.rsplit("/", 1)[-1].split("?")[0] or f"body.{ext}"
        self.s.artifact(
            mime,
            f"{name}",
            body,
            source="http",
            content_type=content_type or mime,
            status=msg.status,
            truncated=msg.truncated,
            method=msg.method or "response",
        )

    # ------------------------------------------------------------------ close
    def close(self) -> None:
        super().close()
        for direction in (0, 1):
            msg = self._current[direction]
            if msg is not None and msg.state in ("body", "chunked") and msg.body:
                msg.truncated = True
                self._carve_body(msg)
                self._current[direction] = None
        total = sum(len(part) for part in self._cookies)
        if total:
            self.s.note("http_cookie_bytes", total)

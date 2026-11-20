"""WebSocket (RFC 6455) frame parsing and message reassembly.

Why it matters for voice work: a lot of browser-based softphones and "QQ 语音"
style web clients stream audio over WebSocket as base64 or raw Opus/PCM frames.
Being able to see message sizes, opcodes and cadence — without decrypting
anything — is usually enough to identify the codec and the call cadence.
"""

from __future__ import annotations

import base64
import struct

from ..core.model import Severity
from ..core.util import printable_ratio
from .base import AppSession, StreamDissector

OPCODE_NAMES = {0: "continuation", 1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}

MAX_MESSAGE = 4 << 20


class WebSocketDissector(StreamDissector):
    name = "WebSocket"

    def __init__(self, session: AppSession) -> None:
        super().__init__(session)
        self._buffers = [bytearray(), bytearray()]
        self._fragment = [bytearray(), bytearray()]
        self._fragment_opcode = [0, 0]
        self._frames = 0
        self._bytes = 0

    def feed(self, direction: int, data: bytes) -> None:
        buf = self._buffers[direction]
        buf += data
        while True:
            if len(buf) < 2:
                return
            b0, b1 = buf[0], buf[1]
            fin = bool(b0 & 0x80)
            opcode = b0 & 0x0F
            masked = bool(b1 & 0x80)
            length = b1 & 0x7F
            pos = 2
            if length == 126:
                if len(buf) < 4:
                    return
                length = struct.unpack_from("!H", buf, 2)[0]
                pos = 4
            elif length == 127:
                if len(buf) < 10:
                    return
                length = struct.unpack_from("!Q", buf, 2)[0]
                pos = 10
            if length > MAX_MESSAGE:
                self.s.emit("ws", f"absurd WebSocket frame length {length}", severity=Severity.LOW)
                buf.clear()
                return
            mask_key = b""
            if masked:
                if len(buf) < pos + 4:
                    return
                mask_key = bytes(buf[pos : pos + 4])
                pos += 4
            if len(buf) < pos + length:
                return
            payload = bytes(buf[pos : pos + length])
            del buf[: pos + length]
            if masked:
                payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
            self._frames += 1
            self._bytes += length
            self._handle_frame(direction, fin, opcode, payload)

    def _handle_frame(self, direction: int, fin: bool, opcode: int, payload: bytes) -> None:
        if opcode in (8, 9, 10):
            if opcode == 8:
                code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 0
                reason = payload[2:].decode("utf-8", "replace")
                self.s.emit("ws", f"WebSocket close {code} {reason}".strip(), code=code)
                self.s.tag("ws-closed")
            return
        if opcode in (1, 2):
            self._fragment_opcode[direction] = opcode
            self._fragment[direction] = bytearray(payload)
        elif opcode == 0:
            if not self._fragment_opcode[direction]:
                # RFC 6455 §5.4: a continuation without an open message is a
                # protocol error — dropping it beats inventing a text message.
                self.s.emit("ws", "WebSocket continuation without a start frame", severity=Severity.LOW)
                return
            self._fragment[direction] += payload
        else:
            return
        if not fin:
            return
        message = bytes(self._fragment[direction])
        self._fragment[direction].clear()
        msg_type = self._fragment_opcode[direction] or 1
        if msg_type == 1:
            self._handle_text(message)
        else:
            self._handle_binary(message)

    def _handle_text(self, message: bytes) -> None:
        text = message.decode("utf-8", "replace")
        if len(message) >= 8192 and printable_ratio(message[:512]) < 0.4:
            # base64-encoded media: decode and carve instead of dumping noise
            try:
                decoded = base64.b64decode(message[: 4 << 20], validate=False)
            except ValueError:
                decoded = b""
            if decoded and len(decoded) > 1024:
                self.s.artifact("application/octet-stream", "ws-base64.bin", decoded, source="websocket")
                self.s.emit(
                    "ws",
                    f"WebSocket text message carrying {len(decoded)} B base64 payload",
                    size=len(message),
                )
                return
        preview = text[:200].replace("\n", "\\n")
        self.s.emit("ws", f"WS text {len(message)} B: {preview}", size=len(message), text=preview)
        self._maybe_signal_audio(message, encoded=False)

    def _handle_binary(self, message: bytes) -> None:
        self.s.emit("ws", f"WS binary {len(message)} B", size=len(message))
        if len(message) > 512:
            self.s.artifact("application/octet-stream", "ws-binary.bin", message, source="websocket")
        self._maybe_signal_audio(message, encoded=True)

    #: Base64 of the first two bytes for common WebSocket audio envelopes.
    #: ``AA``/``AB``/``AC``/``AD`` are the SILK/Opus padding headers browsers
    #: emit when they wrap binary audio in a JSON text frame.
    _AUDIO_B64_PREFIXES = (b"AA", b"AB", b"AC", b"AD")

    def _maybe_signal_audio(self, message: bytes, *, encoded: bool) -> None:
        """Recognise the fingerprints of RTP-ish / Opus-ish payloads in messages."""
        raw = message
        if not encoded and len(raw) >= 64 and raw[:2] in self._AUDIO_B64_PREFIXES:
            # Base64 bodies stay ASCII; random text that happens to start with
            # "AA" does not. Only claim audio when the rest looks encoded.
            if printable_ratio(raw[:256]) > 0.95:
                self.s.tag("ws-base64-audio?")
                self.s.note("ws_audio_text", len(raw))
                self.s.emit(
                    "ws",
                    f"WebSocket text frame looks like base64 audio ({len(raw)} B)",
                    severity=Severity.LOW,
                    size=len(raw),
                )
                return
        if raw.startswith(b"OpusHead"):
            self.s.tag("ws-opus")
            self.s.emit("ws", "Opus stream signalled over WebSocket", severity=Severity.INFO)
        elif raw[:1] in (b"\x02", b"\x03") and len(raw) > 40 and raw[1] == 0x00:
            self.s.tag("ws-silk?")
            self.s.note("ws_silk_suspect", True)

    def close(self) -> None:
        super().close()
        if self._frames:
            self.s.emit(
                "ws",
                f"WebSocket session closed · {self._frames} frames · {self._bytes / 1024:.0f} KiB",
                frames=self._frames,
                bytes=self._bytes,
            )

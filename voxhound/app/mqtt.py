"""MQTT 3.1.1/5.0: connection metadata and topic traffic.

IoT estates are full of MQTT, often unauthenticated and often carrying more than
telemetry. Topic names alone tell an analyst what a device fleet is doing, so
they are worth decoding even without a payload parser for every schema.

The parser is deliberately defensive: MQTT arrives from devices that may be
broken or hostile, and a malformed CONNECT must not take the dissector down.
"""

from __future__ import annotations

import struct

from ..core.model import Severity
from .base import AppSession

PACKET_NAMES = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH",
}

CONNACK_CODES = {
    0: "accepted",
    1: "unacceptable protocol version",
    2: "identifier rejected",
    3: "server unavailable",
    4: "bad username or password",
    5: "not authorized",
}

MAX_BUFFER = 16 << 20  # a stalled 200 MB frame must not grow the process


def read_varint(buf: bytes, pos: int) -> tuple[int, int, bool]:
    """Decode a remaining-length varint.

    Returns ``(value, next_pos, complete)``. ``complete`` is False when the
    buffer ends inside the length field — the caller must wait for more bytes
    instead of treating the partial value as a frame length.
    """
    multiplier = 1
    value = 0
    for _ in range(4):
        if pos >= len(buf):
            return value, pos, False
        byte = buf[pos]
        pos += 1
        value += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            return value, pos, True
        multiplier *= 128
    return value, pos, False  # five continuation bytes: malformed


class MqttDissector:
    """Datagram- and stream-compatible (MQTT runs over TCP, parsed here in stream mode)."""

    name = "MQTT"

    def __init__(self, session: AppSession) -> None:
        self.s = session
        self._buffer = bytearray()
        self.packets = 0

    def feed(self, direction: int, data: bytes) -> None:
        self._buffer += data
        while True:
            if len(self._buffer) < 2:
                return
            header = self._buffer[0]
            remaining, pos, complete = read_varint(bytes(self._buffer), 1)
            if not complete:
                return
            if remaining > MAX_BUFFER:
                self.s.emit("mqtt", f"absurd MQTT length {remaining}", severity=Severity.LOW)
                self._buffer.clear()
                return
            if len(self._buffer) < pos + remaining:
                return
            body = bytes(self._buffer[pos : pos + remaining])
            del self._buffer[: pos + remaining]
            ptype = header >> 4
            flags = header & 0x0F
            self.packets += 1
            self._handle(ptype, flags, body, direction)

    def _handle(self, ptype: int, flags: int, body: bytes, direction: int) -> None:
        name = PACKET_NAMES.get(ptype, f"type{ptype}")
        if ptype == 1:
            self._connect(body)
        elif ptype == 2 and len(body) >= 2:
            code = body[1]
            self.s.emit(
                "mqtt",
                f"CONNACK {CONNACK_CODES.get(code, code)}",
                severity=Severity.LOW if code else Severity.INFO,
                code=code,
            )
        elif ptype == 3:
            self._publish(flags, body)
        elif ptype == 8:
            self._subscribe(body)
        elif ptype in (12, 14):
            self.s.emit("mqtt", name, severity=Severity.INFO)
        else:
            self.s.emit("mqtt", name, bytes=len(body))

    # ------------------------------------------------------------------ packets
    def _connect(self, body: bytes) -> None:
        proto, pos = _read_string(body, 0)
        level = body[pos] if pos < len(body) else 0
        pos += 1
        if pos + 3 > len(body):
            self.s.emit("mqtt", "truncated CONNECT", severity=Severity.LOW)
            return
        pos += 1  # connect flags
        keepalive = struct.unpack_from("!H", body, pos)[0]
        pos += 2
        client_id, _ = _read_string(body, pos)
        self.s.emit(
            "mqtt",
            f"CONNECT client={client_id or '-'} {proto or '?'} v{level} keepalive={keepalive}s",
            client_id=client_id,
            protocol=proto,
            level=level,
            keepalive=keepalive,
        )
        self.s.tag("mqtt")
        if client_id:
            self.s.note("mqtt_client_id", client_id)

    def _publish(self, flags: int, body: bytes) -> None:
        topic, pos = _read_string(body, 0)
        qos = (flags >> 1) & 0x03
        if qos > 0:
            pos += 2  # packet identifier precedes the payload for QoS 1/2
        payload = body[pos:] if pos <= len(body) else b""
        self.s.emit(
            "mqtt",
            f"PUBLISH {topic or '-'} ({len(payload)} B)",
            topic=topic,
            bytes=len(payload),
            qos=qos,
            retained=bool(flags & 0x1),
        )
        if payload and len(payload) >= 256:
            safe_topic = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in topic)[:48]
            self.s.artifact(
                "application/octet-stream",
                f"mqtt-{safe_topic or 'payload'}.bin",
                payload,
                source="mqtt",
                topic=topic,
            )

    def _subscribe(self, body: bytes) -> None:
        pos = 2  # packet identifier
        topics = []
        while pos < len(body):
            topic, pos = _read_string(body, pos)
            if not topic:
                break
            topics.append(topic)
            pos += 1  # requested QoS
        if topics:
            self.s.emit("mqtt", f"SUBSCRIBE {', '.join(topics[:6])}", topics=topics[:16])

    def close(self) -> None:
        if self.packets:
            self.s.emit("mqtt", f"MQTT session closed · {self.packets} packets", packets=self.packets)


def _read_string(buf: bytes, pos: int) -> tuple[str, int]:
    if pos + 2 > len(buf):
        return "", pos
    length = struct.unpack_from("!H", buf, pos)[0]
    pos += 2
    return buf[pos : pos + length].decode("utf-8", "replace"), pos + length

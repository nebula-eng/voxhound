"""VoIP call reconstruction from bare RTP — no SIP, no signalling, no guessing.

This is the feature that makes VoxHound useful for voice work: given two UDP
flows carrying RTP (which is what QQ/WeChat/Teams/browser WebRTC all use at the
transport level), reassemble each SSRC into a playable WAV by

1. ordering packets by RTP sequence number with a bounded reorder window,
2. decoding G.711 (µ-law / A-law) to linear PCM,
3. inserting silence for lost packets so the timeline stays honest,
4. computing RFC 3550 jitter and loss so the report can say *how* bad the call
   was, not just that it existed.

Dynamic payload types (96-127) carry Opus/AAC/G.722 in practice. We cannot
decode those to PCM without a codec library, so they are exported as raw
payload streams plus their timing metadata — honest about the limit, still
useful.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import wav

#: Static RTP payload types (RFC 3551) → (codec, clock rate)
STATIC_PAYLOADS: dict[int, tuple[str, int]] = {
    0: ("PCMU", 8000),
    3: ("GSM", 8000),
    4: ("G723", 8000),
    8: ("PCMA", 8000),
    9: ("G722", 8000),
    13: ("CN", 8000),
    18: ("G729", 8000),
    26: ("JPEG", 90000),
    31: ("H261", 90000),
    32: ("MPV", 90000),
    33: ("MP2T", 90000),
    34: ("H263", 90000),
}

DYNAMIC_CODEC_HINTS = {
    111: ("Opus", 48000),
    112: ("Opus", 48000),
    96: ("dynamic-96", 48000),
    97: ("dynamic-97", 48000),
    100: ("VP8", 90000),
    101: ("H264", 90000),
    102: ("H264", 90000),
    103: ("H264", 90000),
    104: ("H264", 90000),
    105: ("H264", 90000),
    106: ("H264", 90000),
    107: ("H264", 90000),
    108: ("H264", 90000),
    109: ("H264", 90000),
    110: ("H264", 90000),
    113: ("H264", 90000),
    114: ("H264", 90000),
    115: ("H264", 90000),
    116: ("H264", 90000),
    117: ("H264", 90000),
    118: ("H264", 90000),
    119: ("H264", 90000),
    120: ("H264", 90000),
    121: ("H264", 90000),
    122: ("H264", 90000),
    123: ("H264", 90000),
    124: ("H264", 90000),
    125: ("H264", 90000),
    126: ("H264", 90000),
    127: ("H264", 90000),
}


def codec_for(payload_type: int) -> tuple[str, int]:
    if payload_type in STATIC_PAYLOADS:
        return STATIC_PAYLOADS[payload_type]
    return DYNAMIC_CODEC_HINTS.get(payload_type, (f"PT{payload_type}", 48000))


@dataclass(slots=True)
class RtpPacket:
    version: int
    padding: bool
    extension: bool
    csrc_count: int
    marker: bool
    payload_type: int
    seq: int
    timestamp: int
    ssrc: int
    payload: bytes
    header_len: int = 12


def parse_rtp(buf: bytes) -> RtpPacket | None:
    """Return ``None`` when the buffer is not plausibly RTP."""
    if len(buf) < 12:
        return None
    b0, b1 = buf[0], buf[1]
    if b0 >> 6 != 2:
        return None
    padding = bool(b0 & 0x20)
    extension = bool(b0 & 0x10)
    csrc_count = b0 & 0x0F
    marker = bool(b1 & 0x80)
    payload_type = b1 & 0x7F
    seq, timestamp, ssrc = struct.unpack_from("!HII", buf, 2)
    header_len = 12 + csrc_count * 4
    if extension:
        if len(buf) < header_len + 4:
            return None
        ext_len = struct.unpack_from("!H", buf, header_len + 2)[0]
        header_len += 4 + ext_len * 4
    if header_len > len(buf):
        return None
    payload = buf[header_len:]
    if padding and payload:
        pad = payload[-1]
        payload = payload[:-pad] if 0 < pad <= len(payload) else payload
    return RtpPacket(
        version=2,
        padding=padding,
        extension=extension,
        csrc_count=csrc_count,
        marker=marker,
        payload_type=payload_type,
        seq=seq,
        timestamp=timestamp,
        ssrc=ssrc,
        payload=payload,
        header_len=header_len,
    )


def is_rtcp(buf: bytes) -> bool:
    return len(buf) >= 8 and (buf[0] >> 6) == 2 and 192 <= buf[1] <= 223


RTCP_NAMES = {200: "SR", 201: "RR", 202: "SDES", 203: "BYE", 204: "APP", 205: "RTPFB", 206: "PSFB"}


@dataclass(slots=True)
class RtpStats:
    packets: int = 0
    payload_bytes: int = 0
    lost: int = 0
    duplicates: int = 0
    reordered: int = 0
    highest_seq: int = -1
    base_seq: int = -1
    jitter: float = 0.0
    clock_rate: int = 8000
    first_ts: float = 0.0
    last_ts: float = 0.0

    def jitter_ms(self) -> float:
        return self.jitter / self.clock_rate * 1000.0 if self.clock_rate else 0.0

    def loss_percent(self) -> float:
        expected = self.packets + self.lost
        return self.lost / expected * 100.0 if expected else 0.0


@dataclass(slots=True)
class RtpStream:
    """Per-SSRC state: ordering, jitter, and the audio buffer."""

    ssrc: int
    payload_type: int
    codec: str
    clock_rate: int
    stats: RtpStats = field(default_factory=RtpStats)
    _last_arrival: int | None = None
    _last_rtp_ts: int = 0
    _pending: dict[int, tuple[int, bytes]] = field(default_factory=dict)
    _next_seq: int = -1
    _pcm: bytearray = field(default_factory=bytearray)
    _raw: bytearray = field(default_factory=bytearray)
    _max_samples: int = 8000 * 60 * 10  # 10 minutes at 8 kHz

    def __post_init__(self) -> None:
        self.stats.clock_rate = self.clock_rate

    def add(self, pkt: RtpPacket, arrival: float) -> None:
        stats = self.stats
        if stats.base_seq < 0:
            stats.base_seq = pkt.seq
            stats.highest_seq = pkt.seq - 1
            self._next_seq = pkt.seq
            stats.first_ts = arrival
        stats.last_ts = arrival
        stats.packets += 1
        stats.payload_bytes += len(pkt.payload)

        # RFC 3550 A.8: validate sequence numbers against the highest seen
        delta = (pkt.seq - stats.highest_seq) & 0xFFFF
        if delta < 0x8000:
            if delta == 0:
                stats.duplicates += 1
            else:
                stats.highest_seq = pkt.seq
        else:
            stats.reordered += 1

        # Jitter: J += (|D| - J) / 16, D in timestamp units
        if self._last_arrival is not None:
            arrival_delta = (arrival - self._last_arrival) * self.clock_rate
            ts_delta = (pkt.timestamp - self._last_rtp_ts) & 0xFFFFFFFF
            if ts_delta > 0x80000000:
                ts_delta -= 0x100000000
            deviation = abs(arrival_delta - ts_delta)
            stats.jitter += (deviation - stats.jitter) / 16.0
        self._last_arrival = arrival
        self._last_rtp_ts = pkt.timestamp

        self._pending[pkt.seq] = (pkt.timestamp, pkt.payload)
        if len(self._pending) > 256:
            self._drain(force=True)
        else:
            self._drain()

    def _drain(self, *, force: bool = False) -> None:
        if self._next_seq < 0:
            return
        while self._next_seq in self._pending:
            _ts, payload = self._pending.pop(self._next_seq)
            self._append_audio(payload)
            self._next_seq = (self._next_seq + 1) & 0xFFFF
        if force:
            missing = sorted(self._pending)[0] if self._pending else None
            if missing is not None:
                gap = (missing - self._next_seq) & 0xFFFF
                if gap < 0x8000:
                    self.stats.lost += gap
                    silence = self._silence_for(gap)
                    self._append_audio(silence, encoded=True)
                    self._next_seq = missing
                    self._drain()

    def _silence_for(self, packets: int) -> bytes:
        samples_per_packet = max(1, self.clock_rate // 50)
        if self.codec in ("PCMU", "PCMA"):
            return (b"\xff" if self.codec == "PCMU" else b"\xd5") * samples_per_packet * packets
        return b"\x00" * samples_per_packet * packets

    def _append_audio(self, payload: bytes, *, encoded: bool = False) -> None:
        if len(self._pcm) >= self._max_samples * 2:
            return
        if self.codec == "PCMU":
            self._pcm += wav.ulaw_to_pcm(payload)
        elif self.codec == "PCMA":
            self._pcm += wav.alaw_to_pcm(payload)
        else:
            self._raw += payload

    # ------------------------------------------------------------------ output
    def to_wav(self) -> bytes | None:
        self._drain(force=True)
        if self.codec in ("PCMU", "PCMA") and self._pcm:
            return wav.wav_bytes(bytes(self._pcm), rate=self.clock_rate)
        return None

    def raw_payload(self) -> bytes:
        return bytes(self._raw)

    @property
    def duration_s(self) -> float:
        if not self.stats.packets:
            return 0.0
        return self.stats.last_ts - self.stats.first_ts

    def summary(self) -> str:
        return (
            f"{self.codec} ssrc=0x{self.ssrc:08x} {self.stats.packets} pkts "
            f"{self.duration_s:.1f}s loss={self.stats.loss_percent():.1f}% "
            f"jit={self.stats.jitter_ms():.1f}ms"
        )

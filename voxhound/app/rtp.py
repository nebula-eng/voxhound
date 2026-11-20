"""RTP/RTCP dissector: per-SSRC streams, playable audio, honest statistics.

RTP is where voice and video actually live. VoxHound treats each SSRC as an
independent stream with its own reorder window, jitter estimate and audio
buffer, then exports a WAV (G.711) or a raw payload dump (Opus and friends) when
the flow ends. Works with or without SIP signalling — most consumer apps
(QQ/WeChat/Telegram/WebRTC) never send readable SIP at all.
"""

from __future__ import annotations

from ..core.model import Severity
from ..media import voip
from .base import AppSession


class RtpDissector:
    """Datagram-oriented: one instance per UDP flow."""

    name = "RTP"

    def __init__(self, session: AppSession) -> None:
        self.s = session
        self.streams: dict[int, voip.RtpStream] = {}
        self.rtcp_packets = 0
        self.packets = 0

    # ------------------------------------------------------------------ input
    def feed(self, direction: int, data: bytes) -> None:
        self.s.ts = getattr(self.s, "ts", 0.0)
        if voip.is_rtcp(data):
            self.rtcp_packets += 1
            return
        pkt = voip.parse_rtp(data)
        if pkt is None:
            if len(data) >= 12:
                self.s.emit("rtp", f"malformed RTP datagram ({len(data)} B)", severity=Severity.LOW)
            return
        self.packets += 1
        stream = self.streams.get(pkt.ssrc)
        if stream is None:
            codec, rate = voip.codec_for(pkt.payload_type)
            stream = voip.RtpStream(
                ssrc=pkt.ssrc, payload_type=pkt.payload_type, codec=codec, clock_rate=rate
            )
            self.streams[pkt.ssrc] = stream
            self.s.emit(
                "rtp",
                f"RTP stream started ssrc=0x{pkt.ssrc:08x} PT={pkt.payload_type} {codec}@{rate}Hz",
                ssrc=pkt.ssrc,
                payload_type=pkt.payload_type,
                codec=codec,
                clock_rate=rate,
            )
            self.s.tag("rtp")
            if codec in ("PCMU", "PCMA"):
                self.s.tag("voice-g711")
            self.s.note("rtp_codec", codec)
        stream.add(pkt, self.s.ts)

    def close(self) -> None:
        for stream in self.streams.values():
            stats = stream.stats
            self.s.emit(
                "rtp",
                f"RTP stream {stream.summary()}",
                ssrc=stream.ssrc,
                codec=stream.codec,
                packets=stats.packets,
                lost=stats.lost,
                jitter_ms=round(stats.jitter_ms(), 2),
                duration_s=round(stream.duration_s, 2),
                payload_bytes=stats.payload_bytes,
            )
            if stats.loss_percent() > 5:
                self.s.emit(
                    "rtp",
                    f"high packet loss on ssrc=0x{stream.ssrc:08x}: {stats.loss_percent():.1f}%",
                    severity=Severity.MEDIUM,
                )
            wav_data = stream.to_wav()
            if wav_data:
                seconds = stream.duration_s
                self.s.artifact(
                    "audio/wav",
                    f"call-{stream.ssrc:08x}.wav",
                    wav_data,
                    source="rtp",
                    codec=stream.codec,
                    sample_rate=stream.clock_rate,
                    duration_s=round(seconds, 2),
                    packets=stats.packets,
                    loss_percent=round(stats.loss_percent(), 2),
                    jitter_ms=round(stats.jitter_ms(), 2),
                )
            elif stream.raw_payload():
                raw = stream.raw_payload()
                self.s.artifact(
                    f"audio/{stream.codec.lower()}",
                    f"call-{stream.ssrc:08x}.{stream.codec.lower()}",
                    raw,
                    source="rtp",
                    codec=stream.codec,
                    sample_rate=stream.clock_rate,
                    note="raw RTP payload — decode with the matching codec",
                )

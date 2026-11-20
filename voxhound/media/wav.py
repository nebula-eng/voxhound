"""WAV container writer (PCM 16-bit) and G.711 codecs.

Writing a real WAV rather than "a blob of bytes with .raw at the end" is the
difference between an artifact an analyst can play and one they have to fight
with. Both G.711 laws are implemented as table lookups built once at import,
which is fast enough for a 30-minute call (1.4 M samples).
"""

from __future__ import annotations

import struct

_G711_ULAW = [0] * 256
_G711_ALAW = [0] * 256


def _build_tables() -> None:
    for index in range(256):
        u = ~index & 0xFF
        t = ((u & 0x0F) << 3) + 0x84
        t <<= (u & 0x70) >> 4
        _G711_ULAW[index] = -t if u & 0x80 else t

        a = index ^ 0x55
        t = (a & 0x0F) << 4
        segment = (a & 0x70) >> 4
        if segment == 0:
            t += 8
        elif segment == 1:
            t += 0x108
        else:
            t = (t + 0x108) << (segment - 1)
        _G711_ALAW[index] = t if a & 0x80 else -t


_build_tables()


def ulaw_to_pcm(data: bytes) -> bytes:
    out = bytearray(len(data) * 2)
    for i, byte in enumerate(data):
        struct.pack_into("<h", out, i * 2, _G711_ULAW[byte])
    return bytes(out)


def ulaw_encode(pcm: bytes) -> bytes:
    """Linear 16-bit little-endian → µ-law. Used by the simulator to make a tone."""
    out = bytearray(len(pcm) // 2)
    for index in range(len(out)):
        sample = int.from_bytes(pcm[index * 2 : index * 2 + 2], "little", signed=True)
        sign = 0x80 if sample < 0 else 0
        magnitude = min(32635, abs(sample)) + 0x84
        exponent = magnitude.bit_length() - 8
        exponent = 0 if exponent < 0 else min(7, exponent)
        mantissa = (magnitude >> (exponent + 3)) & 0x0F
        out[index] = ~(sign | (exponent << 4) | mantissa) & 0xFF
    return bytes(out)


def alaw_to_pcm(data: bytes) -> bytes:
    out = bytearray(len(data) * 2)
    for i, byte in enumerate(data):
        struct.pack_into("<h", out, i * 2, _G711_ALAW[byte])
    return bytes(out)


def wav_bytes(pcm: bytes, *, rate: int = 8000, channels: int = 1, sample_width: int = 2) -> bytes:
    """Minimal canonical RIFF/WAVE file."""
    byte_rate = rate * channels * sample_width
    block_align = channels * sample_width
    header = b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVE"
    header += b"fmt " + struct.pack(
        "<IHHIIHH", 16, 1, channels, rate, byte_rate, block_align, sample_width * 8
    )
    header += b"data" + struct.pack("<I", len(pcm))
    return header + pcm


def silence(ms: int, *, rate: int = 8000) -> bytes:
    return b"\x00\x00" * int(rate * ms / 1000)

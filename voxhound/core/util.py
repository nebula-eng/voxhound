"""Low-level helpers: byte formatting, entropy, rate formatting, hashing.

Everything here is pure standard library and free of project imports so that it
can be reused by the engine, the CLI and the UI without import cycles.
"""

from __future__ import annotations

import hashlib
import math

_ASCII_PRINTABLE = bytes(range(0x20, 0x7F))

_HEXDUMP_ROW = 16


def hexdump(
    data: bytes | memoryview, *, offset: int = 0, limit: int = 4096, width: int = _HEXDUMP_ROW
) -> str:
    """Classic ``xxd``-style dump with absolute offsets.

    ``limit`` guards against dumping a multi-megabyte reassembled stream into a
    widget; the caller shows a "truncated" hint from the returned length.
    """
    view = memoryview(data)
    end = min(len(view), max(0, limit))
    lines: list[str] = []
    for pos in range(0, end, width):
        chunk = bytes(view[pos : pos + width])
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = f"{hex_part:<{width * 3 - 1}}"
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{offset + pos:08x}  {hex_part}  |{text}|")
    if len(view) > end:
        lines.append(f"... {len(view) - end} more bytes")
    return "\n".join(lines)


def shannon_entropy(data: bytes | memoryview) -> float:
    """Bits of entropy per byte (0..8).

    Used by the anomaly layer to separate compressed/encrypted payloads from
    structured text, and by the DGA heuristic on DNS query labels.
    """
    n = len(data)
    if n == 0:
        return 0.0
    counts = [0] * 256
    buf = bytes(data)
    for b in buf:
        counts[b] += 1
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def printable_ratio(data: bytes | memoryview) -> float:
    """Fraction of bytes that are printable ASCII (used to guess text vs binary)."""
    n = len(data)
    if n == 0:
        return 0.0
    sample = bytes(data[: min(n, 4096)])
    good = sum(1 for b in sample if b in _ASCII_PRINTABLE or b in (9, 10, 13))
    return good / len(sample)


def human_bytes(value: float, *, precision: int = 1) -> str:
    """1234567 -> '1.2 MB' (SI units, matching how operators read traffic counters)."""
    step = 1000.0
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    v = float(value)
    for unit in units:
        if abs(v) < step or unit == units[-1]:
            return f"{v:.0f} {unit}" if unit == "B" else f"{v:.{precision}f} {unit}"
        v /= step
    return f"{v:.{precision}f} PB"


def human_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    if seconds < 3600:
        return f"{seconds // 60:.0f}m {seconds % 60:.0f}s"
    return f"{seconds // 3600:.0f}h {(seconds % 3600) // 60:.0f}m"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clamp(value: float, low: float, high: float) -> float:
    return low if value < low else high if value > high else value


def safe_filename(name: str, *, fallback: str = "artifact") -> str:
    """Strip path separators and control characters from attacker-controlled names."""
    keep = []
    for ch in name:
        if ch.isalnum() or ch in "-_.@+()[]":
            keep.append(ch)
        elif ch in ' /\\:<>"|?*':
            keep.append("_")
    cleaned = "".join(keep).strip("._")
    cleaned = cleaned[:120]
    return cleaned or fallback

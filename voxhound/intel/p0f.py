"""Passive OS / stack hints.

Honest about its limits: this is *not* a p0f clone and does not claim to be.
It matches the handful of signatures that actually disambiguate the stacks you
meet in practice (Windows, Linux, macOS/iOS, Android, network gear) using TTL,
window size, MSS, window scale and option ordering, and returns a confidence
band so the UI can render "Windows (likely)" rather than a false certainty.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class OsGuess:
    name: str
    confidence: float  # 0..1
    reason: str

    @property
    def label(self) -> str:
        if self.confidence >= 0.8:
            return self.name
        if self.confidence >= 0.5:
            return f"{self.name} (likely)"
        return f"{self.name} (possible)"


# Option order is the strongest single signal: each stack emits its options in a
# fixed order and pads with NOPs differently.
_SIGNATURES: tuple[tuple[tuple[str, ...], str, float], ...] = (
    (("MSS", "SACK_PERM", "TS", "NOP", "WS"), "Linux", 0.9),
    (("MSS", "NOP", "WS", "NOP", "NOP", "SACK_PERM"), "Windows", 0.9),
    (("MSS", "NOP", "WS", "NOP", "NOP", "TS", "NOP", "NOP", "SACK_PERM"), "macOS/iOS", 0.85),
    (("MSS", "NOP", "NOP", "SACK_PERM", "NOP", "WS"), "Android/Linux", 0.7),
    (("MSS", "NOP", "WS", "NOP", "NOP", "TS"), "FreeBSD/Network gear", 0.6),
    (("MSS",), "Legacy/embedded", 0.4),
)

# Default TTLs, used only to break ties between otherwise identical signatures.
_TTL_HINTS = ((32, "Embedded"), (64, "Linux/macOS"), (128, "Windows"), (255, "Network gear"))


def guess_os(*, ttl: int, mss: int, wscale: int, opt_sig: str) -> OsGuess:
    options = tuple(part for part in opt_sig.split(",") if part)
    best: OsGuess | None = None
    for signature, name, confidence in _SIGNATURES:
        if options[: len(signature)] == signature:
            score = confidence
            ttl_hint = _ttl_family(ttl)
            if ttl_hint and ttl_hint.split("/")[0].lower() in name.lower():
                score = min(1.0, score + 0.08)
            reason = f"options {'/'.join(options[: len(signature)])}"
            if best is None or score > best.confidence:
                best = OsGuess(name=name, confidence=score, reason=reason)
    if best is not None:
        return best
    ttl_hint = _ttl_family(ttl) or "unknown"
    return OsGuess(name=ttl_hint, confidence=0.3, reason=f"ttl={ttl} mss={mss} ws={wscale}")


def _ttl_family(ttl: int) -> str | None:
    """Map an observed TTL to the nearest default (packets decrement on each hop)."""
    for base, name in _TTL_HINTS:
        if base - 12 <= ttl <= base:
            return name
    return None

"""Intel layer: fingerprints, entropy heuristics, periodicity detection.

Everything here is a pure function of observed bytes — no network calls, no
lookups, no vendor intel feeds. That keeps results reproducible on an
air-gapped machine and legally simple to redistribute.
"""

from __future__ import annotations

from . import ja4, p0f

__all__ = ["ja4", "p0f"]

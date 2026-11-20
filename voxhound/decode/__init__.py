"""Packet decoding: link, network and transport layers.

The public surface is :class:`Decoder`; the submodules exist so each protocol
can be unit-tested in isolation with hand-built byte strings.
"""

from __future__ import annotations

from .decoder import Decoder

__all__ = ["Decoder"]

"""Capture sources: a file, a live interface, or the built-in traffic simulator.

All sources implement the same pull interface so the engine's pump loop is
identical for offline analysis, live sniffing and the demo mode::

    src.open()
    while not src.eof:
        batch = src.read_batch(512)
        ...

Pull with batching (rather than a callback) is what makes backpressure trivial:
if the analysis stage is slower than the wire, the batch simply grows and the
driver drops — which we surface as a counter instead of silently lying about
capture completeness.
"""

from __future__ import annotations

import logging
import os
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator

from ..core.model import RawPacket
from . import npcap, pcapfile, pcapng, rawsock
from .interfaces import default_interface

log = logging.getLogger(__name__)


class SourceError(RuntimeError):
    """The capture cannot be started; the message is user-facing."""


class CaptureSource(ABC):
    """Common contract for everything that can produce frames."""

    kind = "source"
    description = ""
    linktype = 1

    @abstractmethod
    def open(self) -> None: ...

    @abstractmethod
    def read_batch(self, max_packets: int = 512) -> list[RawPacket]: ...

    @abstractmethod
    def close(self) -> None: ...

    @property
    def eof(self) -> bool:
        return False

    def driver_stats(self) -> tuple[int, int]:
        """``(received, dropped)`` from the driver, when it knows."""
        return 0, 0


class FileSource(CaptureSource):
    """Offline capture file (``.pcap``, ``.pcapng``, gzip-compressed either)."""

    kind = "file"

    def __init__(self, path: str | os.PathLike[str], *, replay: bool = False, speed: float = 1.0) -> None:
        self.path = str(path)
        self.description = f"file:{os.path.basename(self.path)}"
        self._replay = replay
        self._speed = max(0.01, float(speed))
        self._iter: Iterator[RawPacket] | None = None
        self._closer: object | None = None
        self._eof = False
        self._base_ts: float | None = None
        self._wall_base: float | None = None
        self.size = os.path.getsize(self.path) if os.path.exists(self.path) else 0

    def open(self) -> None:
        if not os.path.exists(self.path):
            raise SourceError(f"capture file not found: {self.path}")
        stream = pcapfile.as_stream(self.path)
        head = stream.read(4)
        stream.seek(0)
        fmt = pcapfile.sniff_format(head)
        if fmt == "pcapng":
            reader = pcapng.PcapNgReader(stream)
        elif fmt == "pcap":
            reader = pcapfile.PcapReader(stream)
        else:
            stream.close()
            raise SourceError(
                f"{self.path} is not a pcap/pcapng capture (magic {head.hex()}); "
                "convert it first, e.g. `editcap -F pcapng in out.pcapng`"
            )
        self._closer = reader
        self._iter = iter(reader)

    def read_batch(self, max_packets: int = 512) -> list[RawPacket]:
        assert self._iter is not None, "read_batch() before open()"
        out: list[RawPacket] = []
        for _ in range(max_packets):
            try:
                pkt = next(self._iter)
            except StopIteration:
                self._eof = True
                break
            if self.linktype != pkt.linktype:
                self.linktype = pkt.linktype
            if self._replay:
                if self._base_ts is None:
                    self._base_ts = pkt.ts
                    self._wall_base = time.time()
                target = self._wall_base + (pkt.ts - self._base_ts) / self._speed
                delay = target - time.time()
                if delay > 0:
                    time.sleep(min(delay, 0.5))
            out.append(pkt)
        return out

    def close(self) -> None:
        closer = self._closer
        if closer is not None and hasattr(closer, "close"):
            closer.close()  # type: ignore[attr-defined]
        self._closer = None
        self._iter = None

    @property
    def eof(self) -> bool:
        return self._eof


class LiveSource(CaptureSource):
    """Live capture via Npcap/libpcap, with AF_PACKET as the Linux fallback."""

    kind = "live"

    def __init__(
        self,
        interface: str | None = None,
        *,
        snaplen: int = 262_144,
        promisc: bool = True,
        bpf: str = "",
        buffer_mb: int = 16,
        prefer_raw_socket: bool = False,
    ) -> None:
        self.interface = interface or default_interface() or ""
        self.description = f"iface:{self.interface}"
        self._snaplen = snaplen
        self._promisc = promisc
        self._bpf = bpf
        self._buffer_mb = buffer_mb
        self._prefer_raw = prefer_raw_socket
        self._handle: object | None = None
        self._closed = False

    def open(self) -> None:
        if not self.interface:
            raise SourceError("no capture interface available — is Npcap installed?")
        use_raw = self._prefer_raw or (rawsock.available() and not npcap.available())
        errors: list[str] = []
        if use_raw:
            try:
                self._handle = rawsock.RawSocketCapture(
                    self.interface, snaplen=self._snaplen, promisc=self._promisc, buffer_mb=self._buffer_mb
                )
                self.linktype = self._handle.linktype  # type: ignore[attr-defined]
                return
            except rawsock.RawSocketError as exc:
                errors.append(str(exc))
                if self._prefer_raw:
                    raise SourceError(str(exc)) from exc
        try:
            handle = npcap.LiveHandle(
                self.interface,
                snaplen=self._snaplen,
                promisc=self._promisc,
                buffer_mb=self._buffer_mb,
                bpf=self._bpf,
            )
            self._handle = handle
            self.linktype = handle.linktype
            return
        except npcap.NpcapError as exc:
            errors.append(str(exc))
        raise SourceError("cannot start live capture: " + " | ".join(errors))

    def read_batch(self, max_packets: int = 512) -> list[RawPacket]:
        handle = self._handle
        if handle is None:
            return []
        try:
            return handle.read_batch(max_packets)  # type: ignore[no-any-return]
        except Exception as exc:  # noqa: BLE001 - driver errors are opaque
            log.warning("capture read failed on %s: %s", self.interface, exc)
            self._closed = True
            return []

    def driver_stats(self) -> tuple[int, int]:
        handle = self._handle
        if handle is not None and hasattr(handle, "stats"):
            try:
                return handle.stats()  # type: ignore[no-any-return]
            except Exception:  # noqa: BLE001
                return 0, 0
        return 0, 0

    def close(self) -> None:
        if self._handle is not None and hasattr(self._handle, "close"):
            self._handle.close()  # type: ignore[attr-defined]
        self._handle = None

    @property
    def eof(self) -> bool:
        return self._closed


class DemoSource(CaptureSource):
    """Synthetic but protocol-accurate traffic, so the tool is demoable anywhere.

    The generator lives in :mod:`voxhound.simulate` and produces real byte
    streams — not mock objects — so every decoder sees exactly what it would see
    on the wire. This is also what the test-suite uses as a fixture factory.
    """

    kind = "demo"

    def __init__(self, *, duration: float = 20.0, speed: float = 1.0, seed: int = 7) -> None:
        self.description = "demo:simulated-mixed-traffic"
        self._duration = duration
        self._speed = max(0.01, speed)
        self._seed = seed
        self._gen: Iterator[RawPacket] | None = None
        self._base_ts: float | None = None
        self._wall_base: float | None = None
        self._eof = False

    def open(self) -> None:
        from ..simulate import generate_packets

        self._gen = generate_packets(duration=self._duration, seed=self._seed)

    def read_batch(self, max_packets: int = 512) -> list[RawPacket]:
        assert self._gen is not None
        out: list[RawPacket] = []
        for _ in range(max_packets):
            try:
                pkt = next(self._gen)
            except StopIteration:
                self._eof = True
                break
            if self._base_ts is None:
                self._base_ts = pkt.ts
                self._wall_base = time.time()
            target = self._wall_base + (pkt.ts - self._base_ts) / self._speed
            delay = target - time.time()
            if delay > 0.002:
                time.sleep(min(delay, 0.25))
            out.append(pkt)
        return out

    def close(self) -> None:
        self._gen = None

    @property
    def eof(self) -> bool:
        return self._eof


class TeeSource(CaptureSource):
    """Wraps a source and mirrors every frame into a pcap file.

    The tee happens *before* decoding, so what lands on disk is byte-identical to
    what the wire produced — the same guarantee ``tcpdump -w`` gives. Filters are
    applied by the driver (live) or by the engine (files), so the file records
    the capture as the source saw it, not as the analysis narrowed it.
    """

    kind = "tee"

    def __init__(self, inner: CaptureSource, path: str | os.PathLike[str]) -> None:
        self._inner = inner
        self._path = str(path)
        self._writer: pcapfile.PcapWriter | None = None
        self.description = f"{inner.description} -> {os.path.basename(self._path)}"
        self.linktype = inner.linktype

    def open(self) -> None:
        self._inner.open()
        directory = os.path.dirname(os.path.abspath(self._path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._writer = pcapfile.PcapWriter.open(self._path, linktype=self._inner.linktype or 1)

    def read_batch(self, max_packets: int = 512) -> list[RawPacket]:
        batch = self._inner.read_batch(max_packets)
        if self._writer is not None:
            for pkt in batch:
                self._writer.write(pkt)
        return batch

    def driver_stats(self) -> tuple[int, int]:
        return self._inner.driver_stats()

    @property
    def eof(self) -> bool:
        return self._inner.eof

    @property
    def written(self) -> int:
        return self._writer.count if self._writer else 0

    def close(self) -> None:
        self._inner.close()
        if self._writer is not None:
            self._writer.close()
            self._writer = None


def open_source(spec: str | None, **kwargs: object) -> CaptureSource:
    """Create a source from a CLI spec.

    ``demo`` | ``iface:eth0`` | ``eth0`` | ``file:path.pcap`` | ``path.pcap``
    """
    if not spec or spec == "demo":
        return DemoSource(**kwargs)  # type: ignore[arg-type]
    if spec.startswith("iface:"):
        return LiveSource(spec.split(":", 1)[1], **kwargs)  # type: ignore[arg-type]
    if spec.startswith("file:"):
        return FileSource(spec.split(":", 1)[1], **kwargs)  # type: ignore[arg-type]
    lowered = spec.lower()
    if lowered.endswith((".pcap", ".pcapng", ".cap", ".gz")) or os.path.exists(spec):
        return FileSource(spec, **kwargs)  # type: ignore[arg-type]
    return LiveSource(spec, **kwargs)  # type: ignore[arg-type]

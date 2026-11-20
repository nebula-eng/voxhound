"""ctypes binding to libpcap / Npcap.

Why hand-rolled instead of ``python-pypcap`` or ``scapy``:

* the engine must stay dependency-free, and a ctypes shim is ~250 lines,
* Npcap has to be discovered at *runtime* (it is a separate install on
  Windows), so a build-time native dependency would make ``pip install`` fail on
  every machine without the SDK,
* we need precise control over immediate mode, buffer size and timestamp
  precision for capture quality.

Nothing here is imported at module scope on systems without libpcap: the loader
is lazy and :func:`available` reports the truth.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import struct
import sys
from ctypes import POINTER, byref, c_char_p, c_int, c_uint, c_void_p, create_string_buffer

from ..core.model import RawPacket

log = logging.getLogger(__name__)

_ERRBUF = 512
_LINKTYPE_MAX = 1024

# struct pcap_pkthdr differs: Windows MSVC `long` is 32-bit, POSIX is 64-bit.
if sys.platform == "win32":
    _PKTHDR = struct.Struct("<IIII")
else:
    _PKTHDR = struct.Struct("<qqII")


class PcapStat(ctypes.Structure):
    _fields_ = [
        ("ps_recv", c_uint),
        ("ps_drop", c_uint),
        ("ps_ifdrop", c_uint),
    ]


class _BpfProgram(ctypes.Structure):
    _fields_ = [("bf_len", c_uint), ("bf_insns", c_void_p)]


class NpcapError(RuntimeError):
    """libpcap refused an operation; the message is libpcap's own."""


class _Lib:
    """Thin symbol table wrapper; every entry may be ``None`` on old versions."""

    def __init__(self, lib: ctypes.CDLL) -> None:
        self.lib = lib

        def bind(name: str, restype: object, argtypes: list[object]) -> object:
            fn = getattr(lib, name, None)
            if fn is not None:
                fn.restype = restype
                fn.argtypes = argtypes
            return fn

        self.findalldevs = bind("pcap_findalldevs", c_int, [POINTER(c_void_p), c_char_p])
        self.freealldevs = bind("pcap_freealldevs", None, [c_void_p])
        self.create = bind("pcap_create", c_void_p, [c_char_p, c_char_p])
        self.activate = bind("pcap_activate", c_int, [c_void_p])
        self.set_snaplen = bind("pcap_set_snaplen", c_int, [c_void_p, c_int])
        self.set_promisc = bind("pcap_set_promisc", c_int, [c_void_p, c_int])
        self.set_timeout = bind("pcap_set_timeout", c_int, [c_void_p, c_int])
        self.set_buffer_size = bind("pcap_set_buffer_size", c_int, [c_void_p, c_int])
        self.set_immediate_mode = bind("pcap_set_immediate_mode", c_int, [c_void_p, c_int])
        self.set_snapshot_length = bind("pcap_set_snaplen", c_int, [c_void_p, c_int])
        self.open_live = bind("pcap_open_live", c_void_p, [c_char_p, c_int, c_int, c_int, c_char_p])
        self.next_ex = bind("pcap_next_ex", c_int, [c_void_p, POINTER(c_void_p), POINTER(c_void_p)])
        self.compile = bind("pcap_compile", c_int, [c_void_p, POINTER(_BpfProgram), c_char_p, c_int, c_uint])
        self.setfilter = bind("pcap_setfilter", c_int, [c_void_p, POINTER(_BpfProgram)])
        self.freecode = bind("pcap_freecode", None, [POINTER(_BpfProgram)])
        self.datalink = bind("pcap_datalink", c_int, [c_void_p])
        self.stats = bind("pcap_stats", c_int, [c_void_p, POINTER(PcapStat)])
        self.geterr = bind("pcap_geterr", c_char_p, [c_void_p])
        self.close = bind("pcap_close", None, [c_void_p])
        self.lib_version = bind("pcap_lib_version", c_char_p, [])
        self.breakloop = bind("pcap_breakloop", None, [c_void_p])
        self.setnonblock = bind("pcap_setnonblock", c_int, [c_void_p, c_int, c_char_p])
        self.dispatch = bind("pcap_dispatch", c_int, [c_void_p, c_int, c_void_p, c_void_p])
        self.lookupnet = bind("pcap_lookupnet", c_int, [c_char_p, POINTER(c_uint), POINTER(c_uint), c_char_p])


_lib: _Lib | None = None
_load_error: str | None = None


def _candidate_names() -> list[str]:
    if sys.platform == "win32":
        return ["wpcap.dll", "C:/Windows/System32/Npcap/wpcap.dll", "C:/Windows/System32/wpcap.dll"]
    if sys.platform == "darwin":
        return ["libpcap.A.dylib", "libpcap.dylib", "/usr/lib/libpcap.A.dylib"]
    return ["libpcap.so.1", "libpcap.so.0.8", "libpcap.so"]


def load() -> _Lib:
    """Load libpcap once; raises :class:`NpcapError` with an actionable message."""
    global _lib, _load_error
    if _lib is not None:
        return _lib
    if _load_error is not None:
        raise NpcapError(_load_error)
    errors: list[str] = []
    for name in _candidate_names():
        try:
            _lib = _Lib(ctypes.CDLL(name))
            return _lib
        except OSError as exc:
            errors.append(f"{name}: {exc}")
    found = ctypes.util.find_library("pcap")
    if found:
        try:
            _lib = _Lib(ctypes.CDLL(found))
            return _lib
        except OSError as exc:
            errors.append(f"{found}: {exc}")
    _load_error = (
        "libpcap/Npcap not found. Live capture needs Npcap "
        "(https://npcap.com/#download, enable 'WinPcap API-compatible Mode') on Windows, "
        "or libpcap-dev on Linux/macOS. Offline .pcap/.pcapng analysis works without it."
    )
    raise NpcapError(_load_error + " Tried: " + "; ".join(errors))


def available() -> bool:
    try:
        load()
        return True
    except NpcapError:
        return False


def version() -> str:
    try:
        lib = load()
    except NpcapError as exc:
        return f"unavailable ({exc})"
    if lib.lib_version:
        raw = lib.lib_version()
        return raw.decode("utf-8", "replace") if raw else "unknown"
    return "unknown"


class _PcapIf(ctypes.Structure):
    pass


_PcapIf._fields_ = [
    ("next", POINTER(_PcapIf)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", c_void_p),
    ("flags", c_uint),
]


def _sockaddr_to_text(ptr: c_void_p) -> tuple[int, str] | None:
    """Decode ``struct sockaddr*`` we only know by pointer.

    sa_family is the first 16-bit field on every supported platform; for
    AF_INET the address sits at offset 4, for AF_INET6 at offset 8.
    """
    if not ptr:
        return None
    raw = ctypes.string_at(ptr, 28)
    family = struct.unpack("<H", raw[:2])[0]
    if family == 2:  # AF_INET
        return 2, ".".join(str(b) for b in raw[4:8])
    if family in (10, 23, 30):  # AF_INET6 (linux/darwin), AF_INET6 (windows)
        addr = raw[8:24]
        return 6, _format_ipv6(addr)
    return None


def _format_ipv6(raw: bytes) -> str:
    groups = [int.from_bytes(raw[i : i + 2], "big") for i in range(0, 16, 2)]
    best_start, best_len = -1, 0
    cur_start, cur_len = -1, 0
    for i, g in enumerate(groups):
        if g == 0:
            if cur_start < 0:
                cur_start, cur_len = i, 1
            else:
                cur_len += 1
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
        else:
            cur_start, cur_len = -1, 0
    if best_len < 2:
        return ":".join(f"{g:x}" for g in groups)
    head = ":".join(f"{g:x}" for g in groups[:best_start])
    tail = ":".join(f"{g:x}" for g in groups[best_start + best_len :])
    return f"{head}::{tail}"


def list_devices() -> list[dict[str, object]]:
    """Enumerate capture interfaces with descriptions and addresses."""
    lib = load()
    if not lib.findalldevs:
        return []
    alldevs = c_void_p()
    errbuf = create_string_buffer(_ERRBUF)
    if lib.findalldevs(byref(alldevs), errbuf) != 0:
        raise NpcapError(errbuf.value.decode("utf-8", "replace"))
    devices: list[dict[str, object]] = []
    try:
        node = ctypes.cast(alldevs, POINTER(_PcapIf))
        while node:
            entry = node.contents
            name = entry.name.decode("utf-8", "replace") if entry.name else ""
            desc = entry.description.decode("utf-8", "replace") if entry.description else ""
            addrs: list[str] = []
            addr_ptr = ctypes.cast(entry.addresses, c_void_p)
            guard = 0
            while addr_ptr and guard < 64:
                # struct pcap_addr: next, addr, netmask, broadaddr, dstaddr
                block = ctypes.string_at(addr_ptr, ctypes.sizeof(c_void_p) * 5)
                nxt = struct.unpack(
                    "<Q" if ctypes.sizeof(c_void_p) == 8 else "<I", block[: ctypes.sizeof(c_void_p)]
                )[0]
                addr = struct.unpack(
                    "<Q" if ctypes.sizeof(c_void_p) == 8 else "<I",
                    block[ctypes.sizeof(c_void_p) : ctypes.sizeof(c_void_p) * 2],
                )[0]
                decoded = _sockaddr_to_text(c_void_p(addr))
                if decoded:
                    addrs.append(decoded[1])
                addr_ptr = c_void_p(nxt) if nxt else None
                guard += 1
            devices.append(
                {
                    "name": name,
                    "description": desc,
                    "addresses": addrs,
                    "loopback": bool(entry.flags & 0x1),
                    "up": bool(entry.flags & 0x2),
                }
            )
            node = entry.next
    finally:
        lib.freealldevs(alldevs)
    return devices


class LiveHandle:
    """One activated pcap handle. Not thread-safe; drive it from one thread."""

    def __init__(
        self,
        device: str,
        *,
        snaplen: int = 262_144,
        promisc: bool = True,
        timeout_ms: int = 100,
        buffer_mb: int = 16,
        immediate: bool = True,
        bpf: str = "",
    ) -> None:
        lib = load()
        self._lib = lib
        self.device = device
        self._handle: c_void_p | None = None
        self._bpf = bpf
        errbuf = create_string_buffer(_ERRBUF)
        name = device.encode("utf-8")

        if lib.create:
            handle = lib.create(name, errbuf)
            if not handle:
                raise NpcapError(errbuf.value.decode("utf-8", "replace") or "pcap_create failed")
            self._handle = handle
            if lib.set_snaplen:
                lib.set_snaplen(handle, min(snaplen, 262_144))
            if lib.set_promisc:
                lib.set_promisc(handle, 1 if promisc else 0)
            if lib.set_timeout:
                lib.set_timeout(handle, timeout_ms)
            if lib.set_buffer_size and buffer_mb:
                lib.set_buffer_size(handle, buffer_mb * 1024 * 1024)
            if lib.set_immediate_mode and immediate:
                lib.set_immediate_mode(handle, 1)
            rc = lib.activate(handle)
            if rc < 0:
                message = lib.geterr(handle) if lib.geterr else b""
                self.close()
                raise NpcapError(
                    message.decode("utf-8", "replace") if message else f"pcap_activate failed ({rc})"
                )
            if rc > 0:
                log.warning("pcap_activate warning %s on %s", rc, device)
        else:
            handle = lib.open_live(name, min(snaplen, 262_144), 1 if promisc else 0, timeout_ms, errbuf)
            if not handle:
                raise NpcapError(errbuf.value.decode("utf-8", "replace") or "pcap_open_live failed")
            self._handle = handle

        self.linktype = lib.datalink(handle) if lib.datalink else 1
        if self._bpf:
            self.set_filter(self._bpf)

    # ------------------------------------------------------------------ filter
    def set_filter(self, expression: str) -> None:
        lib = self._lib
        assert self._handle is not None
        if not lib.compile or not lib.setfilter:
            raise NpcapError("this libpcap build has no BPF compiler")
        program = _BpfProgram()
        netmask = c_uint(0)
        net, mask = c_uint(0), c_uint(0)
        if lib.lookupnet:
            lib.lookupnet(self.device.encode("utf-8"), byref(net), byref(mask), create_string_buffer(_ERRBUF))
            netmask = mask
        rc = lib.compile(self._handle, byref(program), expression.encode("utf-8"), 1, netmask)
        if rc != 0:
            message = lib.geterr(self._handle) if lib.geterr else b""
            raise NpcapError(f"invalid capture filter {expression!r}: {message.decode('utf-8', 'replace')}")
        try:
            if lib.setfilter(self._handle, byref(program)) != 0:
                raise NpcapError("pcap_setfilter failed")
        finally:
            if lib.freecode:
                lib.freecode(byref(program))
        self._bpf = expression

    # ------------------------------------------------------------------ reading
    def read_batch(self, limit: int = 256) -> list[RawPacket]:
        """Non-blocking-ish batch read; returns empty list on timeout."""
        lib = self._lib
        assert self._handle is not None
        out: list[RawPacket] = []
        header = c_void_p()
        data = c_void_p()
        for _ in range(limit):
            rc = lib.next_ex(self._handle, byref(header), byref(data))
            if rc == 1:
                raw = ctypes.string_at(header, _PKTHDR.size)
                if _PKTHDR.size == 16:
                    sec, frac, caplen, wirelen = _PKTHDR.unpack(raw)
                else:
                    sec, frac, caplen, wirelen = _PKTHDR.unpack(raw)
                payload = ctypes.string_at(data, caplen) if caplen else b""
                out.append(RawPacket(ts=sec + frac / 1_000_000, data=payload, caplen=caplen, wirelen=wirelen))
            elif rc == 0:
                break  # timeout expired, no packet this round
            elif rc == -2:
                break  # offline EOF (not used for live)
            else:
                message = lib.geterr(self._handle) if lib.geterr else b""
                raise NpcapError(message.decode("utf-8", "replace") or f"pcap_next_ex error {rc}")
        return out

    def stats(self) -> tuple[int, int]:
        """``(received, dropped)`` as reported by the kernel/driver."""
        lib = self._lib
        assert self._handle is not None
        st = PcapStat()
        if lib.stats and lib.stats(self._handle, byref(st)) == 0:
            return int(st.ps_recv), int(st.ps_drop) + int(st.ps_ifdrop)
        return 0, 0

    def close(self) -> None:
        if self._handle and self._lib.close:
            self._lib.close(self._handle)
        self._handle = None

    def __enter__(self) -> LiveHandle:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

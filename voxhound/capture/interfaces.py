"""Interface enumeration that works with and without Npcap/libpcap."""

from __future__ import annotations

import re
import socket
import sys
from dataclasses import dataclass, field

from . import npcap


@dataclass(slots=True)
class Interface:
    name: str
    description: str = ""
    addresses: list[str] = field(default_factory=list)
    loopback: bool = False
    up: bool = True

    @property
    def label(self) -> str:
        if self.description:
            return f"{self.description} ({self.name})"
        return self.name


_VIRTUAL_TAGS = (
    "wan miniport",
    "bluetooth",
    "virtual",
    "vmware",
    "hyper-v",
    "vethernet",
    "tap-",
    "loopback",
    "npcap loopback",
)


def _rank_interface(iface: Interface) -> tuple[object, ...]:
    """Sort real, routable adapters before virtual ones (Wi-Fi before WAN Miniport)."""
    description = iface.description.lower()
    virtual = any(tag in description for tag in _VIRTUAL_TAGS)
    routable_v4 = any(
        address.count(".") == 3 and not address.startswith(("169.254.", "127."))
        for address in iface.addresses
    )
    return (iface.loopback, not iface.up, virtual, not routable_v4, not iface.addresses, description)


def list_interfaces() -> list[Interface]:
    """Prefer Npcap's device list (it carries descriptions and addresses)."""
    if npcap.available():
        try:
            return sorted(
                (
                    Interface(
                        name=str(dev["name"]),
                        description=str(dev["description"]),
                        addresses=list(dev["addresses"]),  # type: ignore[arg-type]
                        loopback=bool(dev["loopback"]),
                        up=bool(dev["up"]),
                    )
                    for dev in npcap.list_devices()
                ),
                key=_rank_interface,
            )
        except npcap.NpcapError:
            pass
    # Fallback: names only. Enough to show the operator what exists and to point
    # them at the Npcap install instructions.
    out: list[Interface] = []
    try:
        for index, name in socket.if_nameindex():
            out.append(Interface(name=name, description=f"ifindex {index}", loopback=name in ("lo", "lo0")))
    except (OSError, AttributeError):
        pass
    return out


def default_interface() -> str | None:
    """Best guess at "the interface the internet comes from".

    ``list_interfaces`` already ranks real adapters above WAN Miniports and
    Bluetooth, so the first up, addressed, non-loopback device is the right one.
    """
    interfaces = [iface for iface in list_interfaces() if not iface.loopback]
    for iface in interfaces:
        if iface.up and iface.addresses:
            return iface.name
    return interfaces[0].name if interfaces else None


def capture_backend() -> str:
    """Short, human-readable label for the capture backend (shown in the UI)."""
    if npcap.available():
        return f"libpcap/Npcap · {npcap.version()}"
    if sys.platform.startswith("linux"):
        return "AF_PACKET 原始套接字"
    return "未安装"


def capture_backend_short() -> str:
    """One-line status for the settings card; the full libpcap string stays in the tooltip."""
    if npcap.available():
        version = npcap.version() or ""
        match = re.search(r"Npcap version ([\d.]+)", version)
        return f"Npcap {match.group(1)} · 在线抓包可用" if match else "Npcap · 在线抓包可用"
    if sys.platform.startswith("linux"):
        return "AF_PACKET · 在线抓包可用"
    return "未安装 · 仅离线分析"


def capture_backend_hint() -> str:
    """Installation guidance, kept out of the compact settings card."""
    if npcap.available():
        return "在线抓包可用；全程只读，不注入数据包。"
    if sys.platform.startswith("linux"):
        return "使用 AF_PACKET 原始套接字，无需 libpcap；需要 CAP_NET_RAW 或 root。"
    return "未安装 Npcap（Windows）或 libpcap（POSIX）；离线分析与内置演示不受影响。"

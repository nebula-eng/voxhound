"""Linux ``AF_PACKET`` capture without libpcap.

Useful in containers and on minimal hosts where installing libpcap is
undesirable. Requires ``CAP_NET_RAW`` (root or the capability). Everything else
in the project uses the same :class:`~voxhound.capture.source.CaptureSource`
interface, so the engine cannot tell the difference.
"""

from __future__ import annotations

import socket
import struct
import sys
import time

from ..core.model import LINKTYPE_ETHERNET, RawPacket

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1


class RawSocketError(RuntimeError):
    pass


def available() -> bool:
    return sys.platform.startswith("linux") and hasattr(socket, "AF_PACKET")


class RawSocketCapture:
    """Promiscuous-ish capture straight off the wire."""

    def __init__(
        self,
        interface: str,
        *,
        snaplen: int = 262_144,
        promisc: bool = True,
        buffer_mb: int = 16,
        timeout_s: float = 0.1,
    ) -> None:
        if not available():
            raise RawSocketError("AF_PACKET capture is Linux-only; use Npcap/libpcap elsewhere")
        self.interface = interface
        self.linktype = LINKTYPE_ETHERNET
        self._timeout = timeout_s
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except PermissionError as exc:
            raise RawSocketError(
                "permission denied opening AF_PACKET socket — run as root or grant CAP_NET_RAW"
            ) from exc
        except OSError as exc:
            raise RawSocketError(f"failed to open AF_PACKET socket: {exc}") from exc
        try:
            self._sock.bind((interface, 0))
            if buffer_mb:
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_mb * 1024 * 1024)
            if promisc:
                # promiscuity is best-effort: the socket still captures our own traffic
                import contextlib

                with contextlib.suppress(OSError):
                    mreq = struct.pack("IHH8s", socket.if_nametoindex(interface), PACKET_MR_PROMISC, 0, b"")
                    self._sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
            self._sock.settimeout(timeout_s)
        except OSError as exc:
            self._sock.close()
            raise RawSocketError(f"cannot bind to {interface}: {exc}") from exc
        self._snaplen = snaplen

    def read_batch(self, limit: int = 256) -> list[RawPacket]:
        out: list[RawPacket] = []
        sock = self._sock
        for _ in range(limit):
            try:
                data, addr = sock.recvfrom(self._snaplen)
            except TimeoutError:
                break
            except OSError:
                break
            out.append(
                RawPacket(
                    ts=time.time(), data=data, caplen=len(data), wirelen=len(data), linktype=self.linktype
                )
            )
        return out

    def close(self) -> None:
        import contextlib

        with contextlib.suppress(OSError):
            self._sock.close()

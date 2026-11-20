"""STUN (RFC 5389/8489) — ICE candidate discovery and NAT topology.

STUN is how WebRTC peers find each other, and its attributes leak more than
people expect: local/remote candidate addresses, the software string of the
endpoint, and sometimes usernames that encode the call session. It is also the
cheapest way to tell "this UDP flow is a call" from "this UDP flow is a game".
"""

from __future__ import annotations

import struct

MAGIC_COOKIE = 0x2112A442

METHODS = {
    0x0001: "Binding request",
    0x0101: "Binding success",
    0x0111: "Binding error",
    0x0003: "Allocate request",
    0x0103: "Allocate success",
    0x0004: "Refresh request",
    0x0006: "Send indication",
    0x0008: "CreatePermission request",
    0x0016: "Data indication",
}

ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_SOFTWARE = 0x8022
ATTR_FINGERPRINT = 0x8028
ATTR_PRIORITY = 0x0024
ATTR_USE_CANDIDATE = 0x0025
ATTR_ICE_CONTROLLED = 0x8029
ATTR_ICE_CONTROLLING = 0x802A

ATTR_NAMES = {
    ATTR_USERNAME: "USERNAME",
    ATTR_MESSAGE_INTEGRITY: "MESSAGE-INTEGRITY",
    ATTR_ERROR_CODE: "ERROR-CODE",
    ATTR_MAPPED_ADDRESS: "MAPPED-ADDRESS",
    ATTR_XOR_MAPPED_ADDRESS: "XOR-MAPPED-ADDRESS",
    ATTR_SOFTWARE: "SOFTWARE",
    ATTR_FINGERPRINT: "FINGERPRINT",
    ATTR_PRIORITY: "PRIORITY",
    ATTR_USE_CANDIDATE: "USE-CANDIDATE",
    ATTR_ICE_CONTROLLED: "ICE-CONTROLLED",
    ATTR_ICE_CONTROLLING: "ICE-CONTROLLING",
}


def looks_like_stun(buf: bytes) -> bool:
    return len(buf) >= 20 and (buf[0] & 0xC0) == 0 and struct.unpack_from("!I", buf, 4)[0] == MAGIC_COOKIE


def _address(value: bytes, *, xor: bool = False, txid: bytes = b"") -> str:
    """Decode MAPPED-ADDRESS / XOR-MAPPED-ADDRESS.

    The XOR variant for IPv6 is masked with ``cookie || transaction-id``
    (RFC 5389 §15.2), not with the cookie alone — using a zero-padded mask
    silently returns the wrong address for the last 12 bytes.
    """
    if len(value) < 8:
        return "?"
    family = value[1]
    port = struct.unpack_from("!H", value, 2)[0]
    if xor:
        port ^= (MAGIC_COOKIE >> 16) & 0xFFFF
    if family == 0x01 and len(value) >= 8:
        raw = value[4:8]
        if xor:
            magic = struct.pack("!I", MAGIC_COOKIE)
            raw = bytes(a ^ b for a, b in zip(raw, magic))
        return f"{'.'.join(str(b) for b in raw)}:{port}"
    if family == 0x02 and len(value) >= 20:
        raw = value[4:20]
        if xor:
            mask = struct.pack("!I", MAGIC_COOKIE) + bytes(txid[:12]).ljust(12, b"\x00")
            raw = bytes(a ^ b for a, b in zip(raw, mask))
        return f"[{':'.join(f'{raw[i]:02x}{raw[i + 1]:02x}' for i in range(0, 16, 2))}]:{port}"
    return "?"


def parse_stun(buf: bytes) -> dict[str, object]:
    if len(buf) < 20:
        return {"method": "invalid", "type": 0, "attributes": []}
    msg_type, length, _cookie = struct.unpack_from("!HHI", buf, 0)
    txid = bytes(buf[8:20])
    attributes: list[tuple[int, bytes]] = []
    pos = 20
    end = min(len(buf), 20 + length)
    while pos + 4 <= end:
        attr_type, attr_len = struct.unpack_from("!HH", buf, pos)
        pos += 4
        value = buf[pos : pos + attr_len]
        pos += (attr_len + 3) & ~3
        attributes.append((attr_type, value))
    info: dict[str, object] = {
        "method": METHODS.get(msg_type, f"0x{msg_type:04x}"),
        "type": msg_type,
        "attributes": [ATTR_NAMES.get(t, f"0x{t:04x}") for t, _ in attributes],
    }
    for attr_type, value in attributes:
        if attr_type == ATTR_USERNAME:
            info["username"] = value.decode("utf-8", "replace")
        elif attr_type == ATTR_SOFTWARE:
            info["software"] = value.decode("utf-8", "replace")
        elif attr_type == ATTR_MAPPED_ADDRESS:
            info["mapped"] = _address(value)
        elif attr_type == ATTR_XOR_MAPPED_ADDRESS:
            info["xor_mapped"] = _address(value, xor=True, txid=txid)
        elif attr_type == ATTR_ERROR_CODE and len(value) >= 4:
            info["error"] = f"{value[2] & 0x07}{value[3]:02d} {value[4:].decode('utf-8', 'replace')}"
    return info


class StunDissector:
    """Datagram dissector: NAT traversal and ICE session metadata."""

    name = "STUN"

    def __init__(self, session: object) -> None:
        self.s = session
        self.packets = 0
        self.mapped: set[str] = set()

    def feed(self, direction: int, data: bytes) -> None:
        if len(data) < 20:
            return
        info = parse_stun(data)
        self.packets += 1
        if info.get("method") == "invalid":
            return
        mapped = info.get("xor_mapped") or info.get("mapped")
        if isinstance(mapped, str) and mapped not in self.mapped:
            self.mapped.add(mapped)
        if self.packets <= 6 or "error" in info:
            self.s.emit(  # type: ignore[attr-defined]
                "stun",
                f"{info['method']} {info.get('username', '')} {mapped or ''}".strip(),
                method=info["method"],
                username=info.get("username", ""),
                software=info.get("software", ""),
                mapped=mapped or "",
                attributes=info["attributes"],
            )
        if info.get("software"):
            self.s.note("stun_software", info["software"])  # type: ignore[attr-defined]
        if info.get("username"):
            self.s.note("stun_username", info["username"])  # type: ignore[attr-defined]
        self.s.tag("webrtc")  # type: ignore[attr-defined]

    def close(self) -> None:
        if self.packets:
            self.s.emit(  # type: ignore[attr-defined]
                "stun",
                f"STUN session closed · {self.packets} messages · {len(self.mapped)} reflexive addresses",
                packets=self.packets,
                mapped=sorted(self.mapped)[:8],
            )

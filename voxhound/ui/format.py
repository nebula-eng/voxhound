"""Presentation helpers shared by the pages (pure functions, no Qt imports)."""

from __future__ import annotations

from typing import Any

from ..core.util import human_bytes, human_duration


def _short(value: Any, limit: int = 64) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def flow_detail_rows(row: dict[str, Any]) -> list[tuple[str, str]]:
    """Flatten one flow row into (label, value) pairs for the detail grid."""
    pairs: list[tuple[str, str]] = [
        ("客户端", _short(row.get("client"), 40)),
        ("服务端", _short(row.get("server"), 40)),
        ("应用", _short(row.get("app") or "-", 24)),
        ("SNI", _short(row.get("sni") or "-", 48)),
        ("JA4", _short(row.get("ja4") or "-", 44)),
        ("JA4S", _short(row.get("ja4s") or "-", 44)),
        ("JA4T", _short(row.get("ja4t") or "-", 44)),
        ("JA3", _short(row.get("ja3") or "-", 44)),
        ("操作系统", _short(row.get("os") or "-", 28)),
        ("TLS 版本", _short(row.get("tls_version") or "-", 16)),
        ("加密套件", _short(row.get("cipher") or "-", 36)),
        ("证书 CN", _short(row.get("cert_cn") or "-", 40)),
        ("包数", f"{int(row.get('packets') or 0):,}"),
        ("字节", human_bytes(int(row.get("bytes") or 0))),
        ("时长", human_duration(float(row.get("duration") or 0))),
        ("状态", "已关闭" if row.get("state") == "closed" else "进行中"),
        ("标签", _short(row.get("tags") or "-", 46)),
    ]
    rtt = row.get("rtt_ms")
    if rtt is not None:
        pairs.append(("握手 RTT", f"{float(rtt):.1f} ms"))
    return pairs

"""Filtered pcap extraction and tabular exports.

Extraction is a *second pass* over the source rather than a replay of what the
engine kept in memory. That is what makes ``voxhound extract`` work on a 20 GiB
capture without a 20 GiB RAM bill, and it means the output is byte-identical to
the input for matching frames (no re-encoding of link-layer headers).
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, TextIO

from ..capture.filter import compile_filter
from ..capture.pcapfile import PcapWriter
from ..capture.source import FileSource
from ..core.model import RawPacket
from ..decode import Decoder


def iter_filtered(
    path: str | Path, expression: str = "", *, limit: int = 0, verify_checksums: bool = False
) -> Iterator[RawPacket]:
    """Yield raw frames whose decoded form matches ``expression``."""
    predicate = compile_filter(expression)
    source = FileSource(str(path))
    source.open()
    decoder = Decoder(verify_checksums=verify_checksums)
    emitted = 0
    try:
        number = 0
        while True:
            batch = source.read_batch(2048)
            if not batch:
                if source.eof:
                    break
                continue
            for raw in batch:
                number += 1
                pkt = decoder.decode(raw, number)
                if pkt is None or not predicate(pkt):
                    continue
                yield raw
                emitted += 1
                if limit and emitted >= limit:
                    return
    finally:
        source.close()


def extract_pcap(
    src: str | Path,
    dst: str | Path,
    expression: str = "",
    *,
    limit: int = 0,
    linktype: int | None = None,
) -> dict[str, Any]:
    """Write matching frames to ``dst``; returns counters for the CLI to print."""
    read = 0
    written = 0
    target = Path(dst)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "wb") as fh:
        writer = PcapWriter(fh, linktype=linktype or 1)
        for raw in iter_filtered(src, expression, limit=limit):
            read += 1
            if linktype is None and writer.count == 0:
                writer.linktype = raw.linktype
            writer.write(raw)
            written += 1
    return {"written": written, "destination": str(target), "filter": expression}


def write_ndjson(rows: list[dict[str, Any]], path: str | Path, *, kind: str = "events") -> Path:
    """One JSON object per line — the format every log pipeline already speaks."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    # newline="" keeps the record separator at exactly one "\n": text mode
    # would rewrite it to "\r\n" on Windows and break naive line splitters.
    with open(target, "w", encoding="utf-8", newline="") as fh:
        for row in rows:
            fh.write(json.dumps({"type": kind, **row}, ensure_ascii=False, default=str))
            fh.write("\n")
    return target


def write_flows_csv(rows: list[dict[str, Any]], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "src",
        "sport",
        "dst",
        "dport",
        "proto",
        "app",
        "sni",
        "ja3",
        "ja4",
        "ja4s",
        "ja4t",
        "os",
        "tls_version",
        "cipher",
        "cert_cn",
        "packets",
        "bytes",
        "duration",
        "state",
        "tags",
    ]
    with open(target, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fields})
    return target


def write_text_report(report: Any, stream: TextIO) -> None:
    """Plain-text summary for terminals and post-mortem notes."""
    stats = report.stats
    stream.write("VoxHound 分析结果\n")
    stream.write("=" * 72 + "\n")
    stream.write(f"数据包  {stats.get('packets', 0):>10,}   字节 {stats.get('wire_bytes', 0):>14,}\n")
    stream.write(f"会话    {len(report.flows):>10,}   发现 {len(report.alerts):>11,}\n")
    stream.write(f"产物    {len(report.artifacts):>10,}   时长 {report.duration:>10.1f}s\n")
    if report.apps:
        stream.write("\n协议构成\n")
        for app, count in list(report.apps.items())[:10]:
            stream.write(f"  {app:<14} {count:>6}\n")
    if report.alerts:
        stream.write("\n发现\n")
        for alert in report.alerts[:20]:
            stream.write(f"  [{alert['severity_label']:>8}] {alert['title']}\n")
    if report.artifacts:
        stream.write("\n产物\n")
        for art in report.artifacts[:20]:
            stream.write(f"  {art['kind']:<22} {art['size']:>9,} B  {art['name']}\n")

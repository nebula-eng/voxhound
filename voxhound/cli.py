"""Command line interface.

Three verbs matter operationally:

``voxhound analyze capture.pcapng``  — offline triage, exits with a code that CI
can gate on (2 when a critical finding is present).
``voxhound sniff -i eth0``           — live capture with optional pcap tee.
``voxhound demo``                    — a full-feature run with no privileges.

Everything else (``extract``, ``interfaces``, ``rules``, ``gui``, ``version``) is
there so the tool is usable in scripts without importing Python.

Console output stays ASCII-only on purpose: Windows terminals default to legacy
code pages, and a report tool that crashes on its own log lines is embarrassing.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
import unicodedata
from pathlib import Path
from threading import Event
from typing import Any

from . import __version__
from .capture import npcap
from .capture.filter import FilterSyntaxError
from .capture.interfaces import (
    capture_backend,
    capture_backend_short,
    default_interface,
    list_interfaces,
)
from .capture.source import SourceError, TeeSource, open_source
from .core.model import Severity
from .core.util import human_bytes, human_duration
from .engine import Engine, Report
from .export.io import extract_pcap, write_flows_csv, write_ndjson
from .export.report import render_markdown, write_html
from .store.sqlite import SessionStore, write_artifacts

# pythonw (used by the GUI entry points on Windows) leaves sys.stdout as None;
# probing it directly would crash before the window ever opens.
_COLOR = bool(getattr(sys.stdout, "isatty", lambda: False)()) and not os.environ.get("NO_COLOR")
_DIM = "\033[2m" if _COLOR else ""
_BOLD = "\033[1m" if _COLOR else ""
_RESET = "\033[0m" if _COLOR else ""
_RED = "\033[31m" if _COLOR else ""
_YELLOW = "\033[33m" if _COLOR else ""
_CYAN = "\033[36m" if _COLOR else ""
_GREEN = "\033[32m" if _COLOR else ""


def _pad(text: str, width: int) -> str:
    """按显示宽度补空格：中文按两列计算，否则严重程度列会错位。"""
    shown = sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)
    return text + " " * max(0, width - shown)


def _sev_color(severity: int) -> str:
    if not _COLOR:
        return ""
    return {4: "\033[41m", 3: _RED, 2: _YELLOW, 1: _CYAN}.get(int(severity), _DIM)


def _print_banner(target: str) -> None:
    sys.stdout.write(f"{_BOLD}VoxHound {__version__}{_RESET}  {_DIM}{target}{_RESET}\n")
    sys.stdout.write(f"{_DIM}全程只读：不注入数据包，不使用窃取密钥解密{_RESET}\n\n")


def _progress_line(snapshot: dict[str, Any]) -> str:
    return (
        f"  {snapshot['packets']:>9,} 包  {human_bytes(snapshot['bytes']):>9}  "
        f"{snapshot['flows']:>7,} 会话  {snapshot['events']:>6,} 事件  "
        f"{snapshot['alerts']:>4,} 发现  {snapshot['pps']:>7.0f} 包/秒"
    )


def _make_progress(quiet: bool, interval_lines: bool):
    last = {"t": 0.0}

    def _callback(snapshot: dict[str, Any]) -> None:
        if quiet:
            return
        now = time.time()
        if _COLOR:
            sys.stderr.write("\r" + _progress_line(snapshot) + "\033[K")
            sys.stderr.flush()
        elif now - last["t"] > 5.0:
            last["t"] = now
            sys.stderr.write(_progress_line(snapshot) + "\n")
            sys.stderr.flush()

    return _callback


def _finish_progress() -> None:
    if _COLOR:
        sys.stderr.write("\n")


def _emit_outputs(report: Report, args: argparse.Namespace) -> int:
    """Write every requested output; returns a process exit code."""
    if getattr(args, "report", None):
        path = write_html(report, args.report)
        sys.stdout.write(f"  报告        {path}\n")
    if getattr(args, "markdown", None):
        with open(args.markdown, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(render_markdown(report))
        sys.stdout.write(f"  Markdown    {args.markdown}\n")
    if getattr(args, "json", None):
        payload = {
            "summary": report.summary(),
            "stats": report.stats,
            "flows": report.flows,
            "events": report.events,
            "alerts": report.alerts,
            "artifacts": report.artifacts,
            "protocols": report.protocols,
            "apps": report.apps,
            "hosts": report.hosts,
        }
        with open(args.json, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
        sys.stdout.write(f"  JSON        {args.json}\n")
    if getattr(args, "ndjson", None):
        write_ndjson(report.events, args.ndjson, kind="event")
        sys.stdout.write(f"  NDJSON      {args.ndjson}\n")
    if getattr(args, "csv", None):
        write_flows_csv(report.flows, args.csv)
        sys.stdout.write(f"  CSV         {args.csv}\n")
    if getattr(args, "store", None):
        with SessionStore(args.store) as store:
            session_id = store.start_session(
                source=str(getattr(args, "source", "") or "live"),
                filter_expr=report.stats.get("capture_filter", ""),
                tool_version=report.version,
            )
            store.add_flows(report.flows)
            store.add_events(report.events)
            store.add_alerts(report.alerts)
            store.add_artifacts(report.artifacts)
            store.finish_session({**report.stats, "flows": len(report.flows), "alerts": len(report.alerts)})
        sys.stdout.write(f"  数据库      {args.store}（会话 {session_id}）\n")
    if getattr(args, "artifacts", None):
        written = write_artifacts(_artifact_objects(report, args), args.artifacts)
        sys.stdout.write(f"  产物        {len(written)} 个文件 -> {args.artifacts}\n")
    critical = sum(1 for alert in report.alerts if int(alert["severity"]) >= int(Severity.CRITICAL))
    high = sum(1 for alert in report.alerts if int(alert["severity"]) == int(Severity.HIGH))
    if critical:
        return 2
    if high:
        return 1
    return 0


def _artifact_objects(report: Report, args: argparse.Namespace) -> list[Any]:
    """The report only carries metadata; re-run is wasteful, so artifacts are
    exported by the engine callback instead when a directory was requested."""
    return list(getattr(args, "_artifact_objects", []))


def _summary_block(report: Report) -> None:
    stats = report.stats
    sys.stdout.write("\n")
    sys.stdout.write(f"{_BOLD}汇总{_RESET}\n")
    sys.stdout.write(f"  数据包    {stats.get('packets', 0):>12,}\n")
    sys.stdout.write(f"  字节      {human_bytes(stats.get('wire_bytes', 0)):>12}\n")
    sys.stdout.write(f"  会话      {len(report.flows):>12,}\n")
    sys.stdout.write(f"  发现      {len(report.alerts):>12,}\n")
    sys.stdout.write(f"  产物      {len(report.artifacts):>12,}\n")
    sys.stdout.write(f"  时长      {human_duration(report.duration):>12}\n")
    if report.apps:
        top = "、".join(f"{name} {count}" for name, count in list(report.apps.items())[:6])
        sys.stdout.write(f"  协议      {top}\n")
    if report.alerts:
        sys.stdout.write(f"\n{_BOLD}发现{_RESET}\n")
        ranked = sorted(report.alerts, key=lambda a: (-int(a["severity"]), -float(a["ts"])))
        for alert in ranked[:12]:
            label = Severity(int(alert["severity"])).label
            sys.stdout.write(
                f"  {_sev_color(int(alert['severity']))}{_pad(label, 8)}{_RESET}  {alert['title'][:96]}\n"
            )
        if len(ranked) > 12:
            sys.stdout.write(f"  {_DIM}…… 其余 {len(ranked) - 12} 条见报告{_RESET}\n")
    if report.artifacts:
        sys.stdout.write(f"\n{_BOLD}产物{_RESET}\n")
        for art in report.artifacts[:10]:
            sys.stdout.write(f"  {art['kind']:<24} {art['size']:>9,} B  {art['name']}\n")
    sys.stdout.write("\n")


def _build_engine(args: argparse.Namespace) -> Engine:
    # A live capture already applies the filter in the kernel. Re-compiling the
    # same string in user space rejects valid BPF the engine's subset does not
    # understand (tcp[tcpflags], vlan, ...), so keep it for display only.
    live = getattr(args, "command", "") == "sniff"
    engine = Engine(
        filter_expr="" if live else (getattr(args, "filter", "") or ""),
        verify_checksums=getattr(args, "verify_checksums", False),
        enable_rules=not getattr(args, "no_rules", False),
        enable_anomaly=not getattr(args, "no_heuristics", False),
        keep_packets=0,
    )
    if live:
        engine.filter_expr = getattr(args, "filter", "") or ""
    rules_path = getattr(args, "rules", None)
    if rules_path:
        added = engine.add_rules_from(rules_path)
        sys.stdout.write(f"  规则        {added} 条，来自 {rules_path}\n")
    return engine


def _attach_artifacts(engine: Engine, args: argparse.Namespace) -> None:
    if not getattr(args, "artifacts", None):
        return
    bucket: list[Any] = []
    args._artifact_objects = bucket
    engine.on_artifact = bucket.append


def _run(args: argparse.Namespace) -> int:
    _print_banner(getattr(args, "source", "") or args.command)
    try:
        engine = _build_engine(args)
    except FilterSyntaxError as exc:
        sys.stderr.write(f"错误：过滤表达式无法解析：{exc}\n")
        sys.stderr.write("离线分析支持 host / net / port / portrange / tcp / udp / and / or / not。\n")
        return 3
    _attach_artifacts(engine, args)
    engine.on_progress = _make_progress(getattr(args, "quiet", False), True)

    stop = Event()

    def _handle_sigint(_signum: int, _frame: object) -> None:
        sys.stderr.write("\n已中断：正在收尾\n")
        stop.set()

    import contextlib

    with contextlib.suppress(ValueError, OSError):
        signal.signal(signal.SIGINT, _handle_sigint)

    started = time.time()
    try:
        source = open_source(getattr(args, "source", None) or "demo", **_source_kwargs(args))
        write_path = getattr(args, "write", None)
        if write_path:
            source = TeeSource(source, write_path)
        report = engine.run(
            source,
            duration=getattr(args, "duration", None),
            stop_event=stop,
        )
    except SourceError as exc:
        sys.stderr.write(f"错误：{exc}\n")
        return 3
    except FileNotFoundError as exc:
        sys.stderr.write(f"错误：{exc}\n")
        return 3
    _finish_progress()
    if getattr(args, "write", None):
        sys.stdout.write(f"\n  抓包文件    {args.write}\n")
    del started
    _summary_block(report)
    return _emit_outputs(report, args)


def _source_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if args.command == "sniff":
        kwargs["snaplen"] = getattr(args, "snaplen", 262144)
        kwargs["promisc"] = not getattr(args, "no_promisc", False)
        kwargs["buffer_mb"] = getattr(args, "buffer_mb", 16)
        kwargs["prefer_raw_socket"] = getattr(args, "raw_socket", False)
        kwargs["bpf"] = getattr(args, "filter", "") or ""
    if args.command == "demo":
        kwargs["duration"] = getattr(args, "demo_duration", 20.0)
        kwargs["speed"] = getattr(args, "speed", 1.0)
        kwargs["seed"] = getattr(args, "seed", 7)
    if args.command == "analyze" and getattr(args, "replay", False):
        kwargs["replay"] = True
        kwargs["speed"] = getattr(args, "speed", 1.0)
    return kwargs


# --------------------------------------------------------------------------- commands
def cmd_analyze(args: argparse.Namespace) -> int:
    if not Path(args.source).exists():
        sys.stderr.write(f"错误：文件不存在：{args.source}\n")
        return 3
    return _run(args)


def cmd_sniff(args: argparse.Namespace) -> int:
    if not args.interface:
        sys.stderr.write("错误：需要 --interface（可先运行 `voxhound interfaces` 查看）\n")
        return 3
    args.source = f"iface:{args.interface}"
    return _run(args)


def cmd_demo(args: argparse.Namespace) -> int:
    args.source = "demo"
    return _run(args)


def cmd_interfaces(_args: argparse.Namespace) -> int:
    sys.stdout.write(f"抓包后端：{capture_backend_short()}\n")
    if npcap.available():
        sys.stdout.write(f"{_DIM}{capture_backend()}{_RESET}\n")
    sys.stdout.write("\n")
    interfaces = list_interfaces()
    if not interfaces:
        sys.stdout.write(
            "未找到可用网卡。Windows 请安装 Npcap（https://npcap.com，"
            "勾选 WinPcap 兼容模式）；\nLinux 请安装 libpcap 或以 root/CAP_NET_RAW 运行。\n"
        )
        return 1
    active = default_interface()
    for iface in interfaces:
        flag = "回环" if iface.loopback else "启用" if iface.up else "停用"
        label = iface.description or iface.name
        marker = "  ← 默认" if iface.name == active else ""
        sys.stdout.write(f"  {_pad(flag, 6)} {label}{marker}\n")
        # The device path is what `-i` wants, so keep it copyable on its own line.
        sys.stdout.write(f"          {_DIM}{iface.name}{_RESET}\n")
        addresses = ", ".join(iface.addresses[:4]) or "-"
        sys.stdout.write(f"          {_DIM}{addresses}{_RESET}\n")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    engine = Engine(enable_anomaly=False)
    if args.check:
        try:
            added = engine.add_rules_from(args.check)
        except (OSError, ValueError) as exc:
            sys.stderr.write(f"错误：{exc}\n")
            return 3
        sys.stdout.write(f"已从 {args.check} 载入 {added} 条规则\n")
        if not added:
            sys.stderr.write(
                "警告：该路径没有解析出任何规则——检查文件结构（单条规则、规则数组或 'rules' 数组）\n"
            )
        for line in engine.rules.skipped:
            sys.stderr.write(f"警告：跳过格式错误的规则 {line}\n")
    rows = engine.rules.as_rows()
    sys.stdout.write(f"共 {len(rows)} 条规则\n\n")
    for row in rows:
        # Chinese labels are double-width; pad by display width or the columns drift.
        scope = {"event": "事件", "flow": "会话"}.get(str(row["scope"]), str(row["scope"]))
        sys.stdout.write(
            f"  {_pad(str(row['id']), 28)} {_pad(str(row['severity']), 8)} "
            f"{_pad(scope, 6)} {row['name'][:60]}\n"
        )
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    _print_banner(f"{args.source} -> {args.output}")
    result = extract_pcap(args.source, args.output, args.filter, limit=args.limit)
    sys.stdout.write(f"  过滤条件    {result['filter'] or '（无）'}\n")
    sys.stdout.write(f"  已写出      {result['written']:,} 帧 -> {result['destination']}\n")
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    try:
        from .ui.app import launch
    except ImportError as exc:
        sys.stderr.write(f"错误：桌面端需要 PySide6（{exc}）\n")
        sys.stderr.write("安装方式：pip install 'voxhound[gui]'\n")
        return 3
    source = getattr(args, "source", None)
    if (
        source
        and source not in ("demo",)
        and not str(source).startswith(("iface:", "file:"))
        and not os.path.isfile(source)
    ):
        sys.stderr.write(f"错误：文件不存在：{source}\n")
        return 2
    path = str(source)[5:] if source and str(source).startswith("file:") else source
    autostart = (
        bool(path) and path != "demo" and not str(path).startswith("iface:") and os.path.isfile(str(path))
    )
    return int(
        launch(
            spec=source,
            filter_expr=getattr(args, "filter", "") or "",
            autostart=autostart,
        )
    )


def cmd_version(_args: argparse.Namespace) -> int:
    from .capture import npcap

    sys.stdout.write(f"VoxHound {__version__}\n")
    sys.stdout.write(f"Python     {sys.version.split()[0]}\n")
    sys.stdout.write(f"平台       {sys.platform}\n")
    backend = npcap.version() if npcap.available() else "未安装（仅可离线分析）"
    sys.stdout.write(f"libpcap    {backend}\n")
    return 0


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="voxhound",
        description="VoxHound —— 面向语音与媒体流量的被动网络取证工作台",
        epilog="文档：https://github.com/nebula-eng/voxhound   许可证：MIT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"voxhound {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_outputs(p: argparse.ArgumentParser) -> None:
        p.add_argument("--report", metavar="HTML", help="生成自包含 HTML 报告")
        p.add_argument("--markdown", metavar="MD", help="生成 Markdown 摘要")
        p.add_argument("--json", metavar="FILE", help="输出完整 JSON 报告")
        p.add_argument("--ndjson", metavar="FILE", help="按 NDJSON 输出事件流")
        p.add_argument("--csv", metavar="FILE", help="导出会话表为 CSV")
        p.add_argument("--store", metavar="DB", help="将会话写入 SQLite 数据库")
        p.add_argument("--artifacts", metavar="DIR", help="把提取到的载荷写入目录")
        p.add_argument("--rules", metavar="PATH", help="追加规则文件或目录")
        p.add_argument("--no-rules", action="store_true", help="关闭内置规则")
        p.add_argument("--no-heuristics", action="store_true", help="关闭行为检测")
        p.add_argument(
            "-w", "--write", metavar="PCAP", help="同时把抓到的帧写入 pcap 文件（同 tcpdump 的 -w）"
        )
        p.add_argument("--quiet", action="store_true", help="不输出进度")

    analyze = sub.add_parser("analyze", help="离线分析抓包文件")
    analyze.add_argument("source", help=".pcap/.pcapng 文件路径（支持 gzip）")
    analyze.add_argument("--filter", default="", help="BPF 风格过滤，如 'tcp port 443'")
    analyze.add_argument("--verify-checksums", action="store_true", help="校验 IP/TCP/UDP 校验和")
    analyze.add_argument("--replay", action="store_true", help="按原始节奏回放（模拟在线）")
    analyze.add_argument("--speed", type=float, default=1.0, help="回放倍速")
    add_outputs(analyze)
    analyze.set_defaults(func=cmd_analyze)

    sniff = sub.add_parser("sniff", help="在线抓包")
    sniff.add_argument("-i", "--interface", help="网卡名（见 `voxhound interfaces`）")
    sniff.add_argument("--filter", default="", help="BPF 抓包过滤表达式")
    sniff.add_argument("--duration", type=float, default=None, help="N 秒后自动停止")
    sniff.add_argument("--snaplen", type=int, default=262144, help="快照长度（字节）")
    sniff.add_argument("--buffer-mb", type=int, default=16, help="内核抓包缓冲（MB）")
    sniff.add_argument("--no-promisc", action="store_true", help="不请求混杂模式")
    sniff.add_argument("--raw-socket", action="store_true", help="Linux：用 AF_PACKET，绕过 libpcap")
    add_outputs(sniff)
    sniff.set_defaults(func=cmd_sniff)

    demo = sub.add_parser("demo", help="运行内置流量模拟器")
    demo.add_argument("--demo-duration", type=float, default=20.0, help="模拟流量的时长（秒）")
    demo.add_argument("--speed", type=float, default=1.0, help="播放倍速")
    demo.add_argument("--seed", type=int, default=7, help="随机种子（同种子生成同样流量）")
    add_outputs(demo)
    demo.set_defaults(func=cmd_demo)

    extract = sub.add_parser("extract", help="按条件过滤出新的 pcap")
    extract.add_argument("source")
    extract.add_argument("-o", "--output", required=True)
    extract.add_argument("--filter", default="")
    extract.add_argument("--limit", type=int, default=0)
    extract.set_defaults(func=cmd_extract)

    interfaces = sub.add_parser("interfaces", help="列出可用网卡")
    interfaces.set_defaults(func=cmd_interfaces)

    rules = sub.add_parser("rules", help="列出或校验检测规则")
    rules.add_argument("--check", nargs="?", const="", help="要校验的规则文件或目录")
    rules.set_defaults(func=cmd_rules)

    gui = sub.add_parser("gui", help="启动桌面端")
    gui.add_argument("source", nargs="?", help="可选：启动后直接打开的抓包文件或网卡")
    gui.add_argument("--filter", default="")
    gui.set_defaults(func=cmd_gui)

    version = sub.add_parser("version", help="显示版本与抓包后端")
    version.set_defaults(func=cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "rules" and args.check == "":
        parser.error("--check needs a path")
    try:
        return int(args.func(args))
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        sys.stderr.write("\n已中断\n")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""自包含 HTML 报告生成器。

设计约束决定了它的形态：

* **单文件、零外部请求。** 分析师要把报告贴进工单、发给隔离网内的同事；
  不能依赖 CDN 字体，也不能依赖前端图表库。
* **可直接打印。** A4 版式、避免大面积深色、避免卡内分页。
* **证据优先。** 哈希、端点、JA4 字符串、规则 ID 一律用等宽字体呈现且可复制——
  无法复核的报告只是一段传闻。

图表全部是手写 SVG：协议构成用圆环、主机流量用条形、速率用面积图。
几十行几何计算胜过引入 800 KiB 的图表依赖。
"""

from __future__ import annotations

import html
import math
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core.util import human_bytes, human_duration

SEVERITY_COLORS = {
    0: "#5b6b7f",
    1: "#2f81f7",
    2: "#c98a12",
    3: "#e5534b",
    4: "#a11d1d",
}
SEVERITY_LABELS = {0: "信息", 1: "较低", 2: "中", 3: "高", 4: "严重"}
PALETTE = ("#2f6df6", "#00a3a3", "#8a63d2", "#e0952a", "#d94f70", "#4aa96c", "#7a8794", "#b45fd1")

CSS = """
:root{
  --ink:#111827; --muted:#5b6676; --line:#e4e8ef; --bg:#f6f7fb; --card:#ffffff;
  --accent:#2f6df6; --accent-soft:#e8f0ff;
  --mono:ui-monospace,SFMono-Regular,"JetBrains Mono",Consolas,Menlo,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",
  "Hiragino Sans GB",sans-serif;}
.wrap{max-width:1180px;margin:0 auto;padding:0 24px 64px}
header.hero{background:linear-gradient(135deg,#0d1b2a 0%,#132a4a 55%,#1b3a63 100%);color:#fff;
  padding:34px 0 26px;margin-bottom:26px}
header.hero .wrap{padding-bottom:0}
.brand{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
.brand h1{margin:0;font-size:25px;letter-spacing:.3px;font-weight:650}
.brand .tag{color:#9fb6d4;font-size:13px}
.hero .meta{margin-top:10px;color:#c3d4e8;font-size:12.5px;display:flex;gap:22px;flex-wrap:wrap}
.hero .meta b{color:#fff;font-weight:600}
.grid{display:grid;gap:16px}
.kpis{grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:20px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.kpi .label{color:var(--muted);font-size:11.5px;letter-spacing:.5px}
.kpi .value{font-size:22px;font-weight:660;margin-top:6px;font-variant-numeric:tabular-nums}
.kpi .sub{color:var(--muted);font-size:12px;margin-top:2px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:18px}
.card h2{margin:0 0 4px;font-size:15px;font-weight:650;letter-spacing:.2px}
.card .hint{color:var(--muted);font-size:12.5px;margin:0 0 14px}
.two{display:grid;grid-template-columns:minmax(280px,1fr) minmax(320px,1.4fr);gap:18px}
@media(max-width:820px){.two{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:12.8px}
th{text-align:left;color:var(--muted);font-weight:600;font-size:11.5px;letter-spacing:.4px;
  border-bottom:1px solid var(--line);padding:8px 8px}
td{padding:7px 8px;border-bottom:1px solid #f0f2f7;vertical-align:top}
tr:last-child td{border-bottom:none}
.mono{font-family:var(--mono);font-size:12px}
.muted{color:var(--muted)}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;
  color:#fff;white-space:nowrap}
.bar-row{display:grid;grid-template-columns:132px 1fr 66px;align-items:center;gap:10px;margin:6px 0}
.bar{height:9px;border-radius:6px;background:#eef1f7;overflow:hidden}
.bar>span{display:block;height:100%;border-radius:6px}
.small{font-size:12px}
footer{color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:16px;margin-top:8px}
.note{background:#fff8e6;border:1px solid #f2e0b5;border-radius:10px;padding:12px 14px;
  font-size:12.5px;color:#6b5620}
code.hash{font-family:var(--mono);font-size:11.5px;color:#3d4b5c}
@media print{
  body{background:#fff} header.hero{background:#0d1b2a !important;-webkit-print-color-adjust:exact}
  .card{break-inside:avoid;box-shadow:none} .kpis{grid-template-columns:repeat(4,1fr)}
}
"""


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _donut(
    items: list[tuple[str, float]], *, size: int = 190, thickness: int = 26, unit: str = "条流"
) -> str:
    total = sum(v for _, v in items) or 1
    radius = (size - thickness) / 2
    center = size / 2
    angle = -math.pi / 2
    parts: list[str] = []
    for index, (label, value) in enumerate(items):
        sweep = 2 * math.pi * (value / total)
        if sweep <= 0:
            continue
        end = angle + sweep
        large = 1 if sweep > math.pi else 0
        x1 = center + radius * math.cos(angle)
        y1 = center + radius * math.sin(angle)
        x2 = center + radius * math.cos(end)
        y2 = center + radius * math.sin(end)
        color = PALETTE[index % len(PALETTE)]
        parts.append(
            f'<path d="M {x1:.2f} {y1:.2f} A {radius:.2f} {radius:.2f} 0 {large} 1 {x2:.2f} {y2:.2f}" '
            f'stroke="{color}" stroke-width="{thickness}" fill="none" stroke-linecap="butt">'
            f"<title>{_e(label)}：{value:.0f}</title></path>"
        )
        angle = end
    legend = "".join(
        f'<div class="small" style="display:flex;align-items:center;gap:7px;margin:3px 0">'
        f'<span style="width:9px;height:9px;border-radius:2px;background:{PALETTE[i % len(PALETTE)]};display:inline-block"></span>'
        f'<span style="flex:1">{_e(label)}</span>'
        f'<span class="muted mono">{value:.0f}</span></div>'
        for i, (label, value) in enumerate(items)
    )
    return (
        f'<div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap">'
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img">'
        + "".join(parts)
        + f'<text x="{center}" y="{center - 2}" text-anchor="middle" font-size="21" font-weight="650" fill="#111827">{total:.0f}</text>'
        f'<text x="{center}" y="{center + 16}" text-anchor="middle" font-size="10.5" fill="#5b6676">{_e(unit)}</text></svg>'
        f'<div style="flex:1;min-width:150px">{legend}</div></div>'
    )


def _bars(items: list[tuple[str, float]], *, color: str = "#2f6df6", unit: str = "") -> str:
    if not items:
        return '<p class="muted small">暂无数据</p>'
    peak = max(v for _, v in items) or 1
    rows = []
    for label, value in items:
        width = max(2.0, value / peak * 100)
        rows.append(
            f'<div class="bar-row"><div class="small" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" '
            f'title="{_e(label)}">{_e(label)}</div>'
            f'<div class="bar"><span style="width:{width:.1f}%;background:{color}"></span></div>'
            f'<div class="small mono muted" style="text-align:right">{_e(_fmt(value))}{unit}</div></div>'
        )
    return "".join(rows)


def _fmt(value: float) -> str:
    if value >= 1_000_000:
        return f"{value / 1e6:.1f}M"
    if value >= 1_000:
        return f"{value / 1e3:.1f}k"
    return f"{value:.0f}"


def _area(series: list[tuple[int, dict[str, float]]], *, width: int = 760, height: int = 132) -> str:
    if len(series) < 2:
        return '<p class="muted small">采样点不足，无法绘制时间线</p>'
    values = [row.get("packets", 0.0) for _, row in series]
    peak = max(values) or 1
    step = width / max(1, len(values) - 1)
    points = [(i * step, height - (v / peak) * (height - 18) - 6) for i, v in enumerate(values)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    area = f"0,{height} " + line + f" {width},{height}"
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" preserveAspectRatio="none" role="img">'
        f'<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0%" stop-color="#2f6df6" stop-opacity="0.35"/>'
        f'<stop offset="100%" stop-color="#2f6df6" stop-opacity="0.02"/></linearGradient></defs>'
        f'<polygon points="{area}" fill="url(#g)"/>'
        f'<polyline points="{line}" fill="none" stroke="#2f6df6" stroke-width="1.7"/>'
        f'<text x="4" y="12" font-size="10" fill="#5b6676">峰值 {peak:.0f} 包/秒</text></svg>'
    )


def _risk(alerts: list[dict[str, Any]]) -> tuple[int, str, str]:
    weights = {0: 0, 1: 2, 2: 6, 3: 14, 4: 25}
    score = min(100, sum(weights.get(int(a.get("severity", 0)), 0) for a in alerts))
    if score >= 60:
        return score, "严重", "#a11d1d"
    if score >= 30:
        return score, "偏高", "#e5534b"
    if score >= 10:
        return score, "需关注", "#c98a12"
    return score, "低", "#2f6df6"


def render_html(report: Any, *, title: str = "VoxHound 分析报告") -> str:
    stats = report.stats
    flows = report.flows
    alerts = report.alerts
    artifacts = report.artifacts
    apps = Counter(report.apps)
    protocols = Counter(report.protocols)
    score, verdict, verdict_color = _risk(alerts)

    kpis = [
        ("数据包", f"{stats.get('packets', 0):,}", human_bytes(stats.get("wire_bytes", 0))),
        ("会话", f"{len(flows):,}", f"{len(report.hosts):,} 个主机"),
        ("发现", f"{len(alerts):,}", f"风险 {score}/100"),
        ("产物", f"{len(artifacts):,}", human_bytes(sum(a.get("size", 0) for a in artifacts))),
        ("时长", human_duration(report.duration), f"{stats.get('malformed', 0)} 个畸形帧"),
        ("过滤条件", stats.get("capture_filter") or "无", "BPF 子集"),
    ]

    kpi_html = "".join(
        f'<div class="kpi"><div class="label">{_e(label)}</div><div class="value">{_e(value)}</div>'
        f'<div class="sub">{_e(sub)}</div></div>'
        for label, value, sub in kpis
    )

    alert_rows = (
        "".join(
            f'<tr><td class="mono muted">'
            f"{(datetime.fromtimestamp(a['ts']).strftime('%H:%M:%S') if a['ts'] else '-')}</td>"
            f'<td><span class="chip" style="background:{SEVERITY_COLORS.get(int(a["severity"]), "#5b6b7f")}">'
            f"{SEVERITY_LABELS.get(int(a['severity']), '信息')}</span></td>"
            f'<td><b>{_e(a["title"])}</b><div class="muted small">{_e(a.get("description", ""))}</div></td>'
            f'<td class="mono muted">{_e(a.get("rule", ""))}</td>'
            f'<td class="mono muted">{_e(a.get("flow", ""))}</td></tr>'
            for a in alerts[:60]
        )
        or '<tr><td colspan="5" class="muted">未命中任何规则</td></tr>'
    )

    flow_rows = (
        "".join(
            f'<tr><td class="mono">{_e(f["src"])}:{f["sport"]}</td>'
            f'<td class="mono">{_e(f["dst"])}:{f["dport"]}</td>'
            f"<td>{_e(f['proto'])}</td>"
            f"<td>{_e(f['app'] or '-')}</td>"
            f'<td class="mono small">{_e(f["sni"] or "-")}</td>'
            f'<td class="mono small muted">{_e((f["ja4"] or "-")[:34])}</td>'
            f'<td style="text-align:right" class="mono">{human_bytes(f["bytes"])}</td>'
            f'<td style="text-align:right" class="mono muted">{human_duration(f["duration"])}</td></tr>'
            for f in flows[:120]
        )
        or '<tr><td colspan="8" class="muted">没有会话记录</td></tr>'
    )

    artifact_rows = (
        "".join(
            f'<tr><td>{_e(a["kind"])}</td><td class="mono small">{_e(a["name"])}</td>'
            f'<td style="text-align:right" class="mono">{human_bytes(a["size"])}</td>'
            f'<td class="mono small muted">{_e(a["source"])}</td>'
            f'<td><code class="hash">{_e(a["sha256"][:32])}…</code></td></tr>'
            for a in artifacts[:60]
        )
        or '<tr><td colspan="5" class="muted">没有提取到任何产物</td></tr>'
    )

    talkers = [(row["host"], row["bytes"]) for row in report.top_talkers[:10]]

    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)} · {_e(report.version)}</title>
<style>{CSS}</style></head>
<body>
<header class="hero"><div class="wrap">
  <div class="brand"><h1>VoxHound</h1><span class="tag">被动网络取证 · 语音与媒体流量</span></div>
  <div class="meta">
    <span>生成于 <b>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</b></span>
    <span>引擎 <b>{_e(report.version)}</b></span>
    <span>结论 <b style="color:{verdict_color}">{_e(verdict)}（{score}/100）</b></span>
    <span>时长 <b>{_e(human_duration(report.duration))}</b></span>
  </div>
</div></header>

<div class="wrap">
  <div class="grid kpis">{kpi_html}</div>

  <div class="card"><h2>流量时间线</h2>
    <p class="hint">每秒数据包数。突增通常意味着批量传输或扫描，落地页右上角的峰值可用于横向比对。</p>
    {_area(report.series)}
  </div>

  <div class="two">
    <div class="card"><h2>传输层构成</h2><p class="hint">按数据包统计的传输层协议占比。</p>
      {_donut(list(protocols.most_common(6)) or [("无", 1)], unit="个包")}</div>
    <div class="card"><h2>应用层识别</h2><p class="hint">已被解析器识别归属的会话数量。</p>
      {_bars(list(apps.most_common(8))) if apps else '<p class="muted small">未识别出应用层协议</p>'}</div>
  </div>

  <div class="card"><h2>发现</h2>
    <p class="hint">共 {len(alerts)} 条命中，来自声明式规则与行为检测，按严重程度降序排列。</p>
    <table><thead><tr><th>时间</th><th>级别</th><th>结论</th><th>规则</th><th>端点</th></tr></thead>
    <tbody>{alert_rows}</tbody></table>
  </div>

  <div class="two">
    <div class="card"><h2>流量主机</h2><p class="hint">按传输字节排序的主机。</p>
      {_bars(talkers, color="#00a3a3")}</div>
    <div class="card"><h2>已提取产物</h2>
      <p class="hint">从流中还原的载荷。使用前请自行校验哈希。</p>
      <table><thead><tr><th>类型</th><th>文件名</th><th style="text-align:right">大小</th><th>来源</th><th>sha256</th></tr></thead>
      <tbody>{artifact_rows}</tbody></table></div>
  </div>

  <div class="card"><h2>会话明细</h2>
    <p class="hint">体积最大的 {min(len(flows), 120)} 条会话。JA4 标识客户端 TLS 栈，JA4S 标识服务端。</p>
    <table><thead><tr><th>客户端</th><th>服务端</th><th>协议</th><th>应用</th><th>SNI</th><th>JA4</th>
    <th style="text-align:right">字节</th><th style="text-align:right">时长</th></tr></thead>
    <tbody>{flow_rows}</tbody></table>
  </div>

  <div class="note"><b>数据处置提醒。</b>本报告由真实网络流量生成，可能包含个人数据与第三方内容。
  请按你所在组织的留存策略保管；产物是惰性载荷，切勿执行。</div>

  <footer>
    VoxHound {_e(report.version)} · 全程只读：不注入、不使用窃取的密钥解密、不做代理转发。<br>
    生成于 {datetime.now().isoformat(timespec="seconds")} · 数据包 {stats.get("packets", 0):,} ·
    字节 {stats.get("wire_bytes", 0):,} · 会话 {len(flows):,} · 发现 {len(alerts):,}
  </footer>
</div>
</body></html>"""


def write_html(report: Any, path: str | Path, *, title: str = "VoxHound 分析报告") -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    # Explicit newline keeps the committed sample byte-stable across platforms.
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_html(report, title=title))
    return target


def render_markdown(report: Any) -> str:
    """给工单与 PR 用的紧凑 Markdown 摘要。"""
    lines = [
        f"# VoxHound 分析报告 · {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        f"- 数据包 **{report.stats.get('packets', 0):,}** · 会话 **{len(report.flows):,}** · "
        f"发现 **{len(report.alerts):,}** · 产物 **{len(report.artifacts):,}**",
        f"- 时长 **{human_duration(report.duration)}** · 引擎 {report.version}",
        "",
        "## 发现",
        "",
        "| 级别 | 结论 | 规则 |",
        "| --- | --- | --- |",
    ]
    for alert in report.alerts[:40]:
        label = SEVERITY_LABELS.get(int(alert["severity"]), "信息")
        lines.append(f"| {label} | {alert['title']} | `{alert.get('rule', '')}` |")
    lines += ["", "## 主要会话", "", "| 端点 | 应用 | SNI | 字节 |", "| --- | --- | --- | --- |"]
    for flow in report.flows[:25]:
        lines.append(
            f"| `{flow['src']}:{flow['sport']} → {flow['dst']}:{flow['dport']}` | {flow['app'] or '-'} | "
            f"{flow['sni'] or '-'} | {human_bytes(flow['bytes'])} |"
        )
    return "\n".join(lines) + "\n"

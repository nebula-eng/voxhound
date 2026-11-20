"""The six pages of the application.

Each page is independent: it receives models from the main window, exposes small
``update_*`` methods, and never talks to the engine directly. That keeps the
window's wiring flat and makes the pages testable by construction (build one,
feed it rows, grab a screenshot).

Visual grammar, applied consistently:

* one accent colour for state, semantic colours only for severity,
* numbers right-aligned in tabular figures, identifiers in mono,
* empty states that say what to do next instead of showing a blank grid.
"""

from __future__ import annotations

import contextlib
import json
import unicodedata
import wave
from array import array
from io import BytesIO

from PySide6.QtCore import QEvent, QPointF, QRectF, QSize, Qt, QTimer
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ..capture.interfaces import (
    capture_backend,
    capture_backend_hint,
    capture_backend_short,
    list_interfaces,
)
from ..core.util import human_bytes
from ..version import __version__
from .format import flow_detail_rows
from .models import AlertModel, ArtifactModel, FlowModel, PacketModel, RowFilterProxy, RuleModel
from .theme import Palette, severity_label
from .widgets import (
    BarList,
    Card,
    DonutChart,
    ElidedLabel,
    HexView,
    MonoDelegate,
    SeverityChip,
    SeverityDelegate,
    StatTile,
    TrafficChart,
)

APP_COLORS = ("#4C8DFF", "#2FD3A5", "#B07CFF", "#F5A524", "#FF7B9C", "#5AC8FA", "#8FA3BF")
EVENT_LABELS = {
    "dns": "DNS",
    "tls": "TLS",
    "http": "HTTP",
    "http1": "HTTP",
    "http2": "HTTP/2",
    "quic": "QUIC",
    "rtp": "RTP",
    "rtcp": "RTCP",
    "sip": "SIP",
    "stun": "STUN",
    "mqtt": "MQTT",
    "websocket": "WS",
    "ws": "WS",
}
ARTIFACT_LABELS = {
    "audio": "语音",
    "image": "图片",
    "text": "文本",
    "video": "视频",
    "application": "文件",
    "font": "字体",
}


def _table(model: object, palette: Palette) -> QTableView:
    view = QTableView()
    view.setModel(model)  # type: ignore[arg-type]
    view.setAlternatingRowColors(True)
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    view.setShowGrid(False)
    view.verticalHeader().setVisible(False)
    view.verticalHeader().setDefaultSectionSize(26)
    view.horizontalHeader().setHighlightSections(False)
    view.horizontalHeader().setStretchLastSection(False)
    view.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    view.setWordWrap(False)
    view.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    return view


def _left_align(editor: QPlainTextEdit) -> None:
    """强制左对齐：部分样式引擎会把 QPlainTextEdit 内容居中。"""
    from PySide6.QtGui import QTextOption

    option = editor.document().defaultTextOption()
    option.setAlignment(Qt.AlignmentFlag.AlignLeft)
    option.setWrapMode(QTextOption.WrapMode.NoWrap)
    editor.document().setDefaultTextOption(option)


def _set_mono_text(editor: QPlainTextEdit, text: str) -> None:
    """写入文本并重新强制左对齐——setPlainText 会重置文档级默认选项。"""
    from PySide6.QtGui import QTextBlockFormat, QTextCursor

    editor.setPlainText(text)
    cursor = editor.textCursor()
    cursor.select(QTextCursor.SelectionType.Document)
    block = QTextBlockFormat()
    block.setAlignment(Qt.AlignmentFlag.AlignLeft)
    cursor.mergeBlockFormat(block)
    cursor.movePosition(QTextCursor.MoveOperation.Start)
    editor.setTextCursor(cursor)


def _pad(text: str, width: int = 10) -> str:
    """按显示宽度补空格（中文按两列），让等宽面板的标签列对齐。"""
    shown = sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)
    return text + " " * max(0, width - shown)


def _toolbar() -> QHBoxLayout:
    bar = QHBoxLayout()
    bar.setSpacing(8)
    return bar


class Page(QWidget):
    """Common scaffolding: consistent margins and an optional header row."""

    title = "page"
    subtitle = ""

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Page")
        self.palette = palette
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(18, 14, 18, 14)
        self.root.setSpacing(12)


# --------------------------------------------------------------------------- dashboard
class DashboardPage(Page):
    title = "仪表盘"
    subtitle = "全局态势：流量、协议构成与发现"

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(palette, parent)
        grid = QGridLayout()
        grid.setSpacing(12)
        self.tiles = {
            "packets": StatTile("数据包", palette, spark=True),
            "rate": StatTile("吞吐", palette, spark=True, accent=palette.good),
            "flows": StatTile("会话", palette),
            "events": StatTile("协议事件", palette),
            "alerts": StatTile("发现", palette, accent=palette.danger),
            "artifacts": StatTile("产物", palette, accent=palette.info),
        }
        for index, tile in enumerate(self.tiles.values()):
            grid.addWidget(tile, 0, index)
            grid.setColumnStretch(index, 1)
        self.root.addLayout(grid)

        middle = QHBoxLayout()
        middle.setSpacing(12)
        traffic_card = Card("流量", "抓包窗口内每秒数据包数")
        self.chart = TrafficChart(palette)
        traffic_card.add(self.chart, 1)
        middle.addWidget(traffic_card, 3)

        donut_card = Card("传输层构成", "按数据包统计的传输层协议占比")
        self.donut = DonutChart(palette, unit="个包")
        donut_card.add(self.donut, 1)
        middle.addWidget(donut_card, 2)
        self.root.addLayout(middle, 3)

        bottom = QHBoxLayout()
        bottom.setSpacing(12)
        talkers_card = Card("流量主机", "按传输字节排序的主机")
        self.talkers = BarList(palette)
        talkers_card.add(self.talkers, 1)
        bottom.addWidget(talkers_card, 1)

        apps_card = Card("应用识别", "已归属到解析器的会话数")
        self.apps = BarList(palette, accent=palette.info)
        apps_card.add(self.apps, 1)
        bottom.addWidget(apps_card, 1)

        findings_card = Card("实时发现", "规则命中与行为检测")
        self.findings_host = QVBoxLayout()
        self.findings_host.setSpacing(6)
        empty = QLabel("暂无发现——这通常是好消息，而不是页面坏了。")
        empty.setObjectName("Faint")
        self.findings_host.addWidget(empty)
        self.findings_host.addStretch(1)
        findings_card.add_layout(self.findings_host, 1)
        bottom.addWidget(findings_card, 1)
        self.root.addLayout(bottom, 4)

        self._finding_rows = 0

    # ------------------------------------------------------------------ updates
    def update_stats(self, snapshot: dict[str, object]) -> None:
        packets = int(snapshot.get("packets", 0) or 0)
        self.tiles["packets"].set(f"{packets:,}", f"已捕获 {human_bytes(float(snapshot.get('bytes', 0)))}")
        pps = float(snapshot.get("pps", 0.0))
        self.tiles["rate"].set(f"{pps:,.0f} 包/秒", f"{human_bytes(float(snapshot.get('bps', 0)))}/秒")
        self.tiles["rate"].push(pps)
        self.tiles["packets"].push(float(packets))
        self.tiles["flows"].set(
            f"{int(snapshot.get('flows', 0)):,}", f"{int(snapshot.get('open_flows', 0)):,} 个活跃"
        )
        kinds = snapshot.get("event_kinds") or {}
        if isinstance(kinds, dict):
            kinds = {k: v for k, v in kinds.items() if str(k) not in ("flow", "other")}
        if isinstance(kinds, dict) and kinds:
            top = " · ".join(
                f"{EVENT_LABELS.get(str(k), str(k))} {int(v)}" for k, v in list(kinds.items())[:2]
            )
        else:
            top = f"过滤 {int(snapshot.get('filtered', 0)):,} · 畸形 {int(snapshot.get('malformed', 0)):,}"
        self.tiles["events"].set(f"{int(snapshot.get('events', 0)):,}", top)
        self.tiles["alerts"].set(
            f"{int(snapshot.get('alerts', 0)):,}", f"{int(snapshot.get('alerts_high', 0)):,} 条高危"
        )
        artifacts = snapshot.get("artifact_kinds") or {}
        if isinstance(artifacts, dict) and artifacts:
            detail = " · ".join(
                f"{ARTIFACT_LABELS.get(str(k), '文件')} {int(v)}" for k, v in list(artifacts.items())[:2]
            )
        else:
            detail = "待提取"
        self.tiles["artifacts"].set(f"{int(snapshot.get('artifacts', 0)):,}", detail)
        series = snapshot.get("series") or []
        if series:
            self.chart.set_values([float(v) for v in series])  # type: ignore[arg-type]
        protocols = snapshot.get("protocols") or {}
        if protocols:
            self.donut.set_slices(
                [
                    (str(name), float(value), APP_COLORS[i % len(APP_COLORS)])
                    for i, (name, value) in enumerate(list(protocols.items())[:6])
                ]
            )
        apps = snapshot.get("apps") or {}
        if apps:
            self.apps.set_rows([(str(name), float(count), f"{int(count)}") for name, count in apps.items()])
        talkers = snapshot.get("talkers") or []
        if talkers:
            rows = []
            for item in talkers:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    rows.append((str(item[0]), float(item[1]), human_bytes(float(item[1]))))
            self.talkers.set_rows(rows)

    def add_alerts(self, alerts: list[dict[str, object]]) -> None:
        if not alerts:
            return
        if self._finding_rows == 0:
            while self.findings_host.count():
                item = self.findings_host.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()
        for alert in alerts[:6]:
            row = QWidget()
            layout = QHBoxLayout(row)
            layout.setContentsMargins(0, 2, 0, 2)
            layout.setSpacing(8)
            severity = int(alert.get("severity", 0))  # type: ignore[arg-type]
            layout.addWidget(SeverityChip(severity, self.palette))
            title = ElidedLabel(str(alert.get("title", "")))
            title.setStyleSheet("font-size: 11.5px;")
            layout.addWidget(title, 1)
            stamp = QLabel(str(alert.get("time", "")))
            stamp.setObjectName("Faint")
            layout.addWidget(stamp)
            self.findings_host.insertWidget(0, row)
            self._finding_rows += 1
        while self.findings_host.count() > 7:
            item = self.findings_host.takeAt(self.findings_host.count() - 1)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            else:
                break

    def reset(self) -> None:
        self._finding_rows = 0


# --------------------------------------------------------------------------- flows
class FlowsPage(Page):
    title = "会话"
    subtitle = "会话记录、指纹与证书身份"

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(palette, parent)
        self.model = FlowModel()
        self.proxy = RowFilterProxy()
        self.proxy.setSourceModel(self.model)
        self.table = _table(self.proxy, palette)
        self._apply_widths(narrow=False)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setItemDelegate(MonoDelegate((0, 1, 5), size=10.0))
        self.table.selectionModel().selectionChanged.connect(self._on_select)
        self.table.viewport().installEventFilter(self)

        bar = _toolbar()
        self.search = QLineEdit()
        self.search.setPlaceholderText("按主机、JA4、应用或端口过滤…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.proxy.set_needle)
        bar.addWidget(self.search, 1)
        self.app_filter = QComboBox()
        self.app_filter.addItem("全部应用", "")
        self.app_filter.currentIndexChanged.connect(
            lambda: self.proxy.set_app(str(self.app_filter.currentData() or ""))
        )
        bar.addWidget(self.app_filter)
        self.count_label = QLabel("0 条会话")
        self.count_label.setObjectName("Faint")
        bar.addWidget(self.count_label)
        self.root.addLayout(bar)

        splitter = QSplitter(Qt.Orientation.Vertical)
        table_card = Card()
        table_card.add(self.table, 1)
        splitter.addWidget(table_card)

        self.detail = Card("会话详情", "选中一行查看指纹与证书身份")
        self.detail_grid = QGridLayout()
        self.detail_grid.setHorizontalSpacing(12)
        self.detail_grid.setVerticalSpacing(5)
        for column in (1, 3, 5, 7):
            self.detail_grid.setColumnStretch(column, 1)
        self.detail.add_layout(self.detail_grid, 1)
        self.detail.setMinimumHeight(168)
        splitter.addWidget(self.detail)
        splitter.setSizes([600, 186])
        self.root.addWidget(splitter, 1)

    def _apply_widths(self, *, narrow: bool) -> None:
        """Trade the JA4 column for readable endpoints when the window is small."""
        self.table.setColumnHidden(5, narrow)
        widths = (
            (156, 156, 52, 78, 0, 0, 58, 70, 66, 64) if narrow else (164, 164, 60, 92, 0, 150, 66, 82, 70, 70)
        )
        for column, width in enumerate(widths):
            if width:
                self.table.setColumnWidth(column, width)

    def _sync_widths(self) -> None:
        narrow = self.table.viewport().width() < 900
        if narrow != getattr(self, "_narrow", None):
            self._narrow = narrow
            self._apply_widths(narrow=narrow)

    def eventFilter(self, watched: object, event: object) -> bool:  # noqa: N802
        if watched is self.table.viewport() and event.type() == QEvent.Type.Resize:  # type: ignore[attr-defined]
            self._sync_widths()
        return super().eventFilter(watched, event)  # type: ignore[arg-type]

    def refresh(self, rows: list[dict[str, object]]) -> None:
        selected = self._selected_key()
        self.model.reset_rows(rows)
        self.count_label.setText(f"{len(rows):,} 条会话")
        apps = sorted({str(row.get("app")) for row in rows if row.get("app")})
        current = self.app_filter.currentData()
        if [self.app_filter.itemData(i) for i in range(self.app_filter.count())][1:] != apps:
            self.app_filter.blockSignals(True)
            self.app_filter.clear()
            self.app_filter.addItem("全部应用", "")
            for app in apps:
                self.app_filter.addItem(app, app)
            index = self.app_filter.findData(current)
            self.app_filter.setCurrentIndex(max(0, index))
            self.app_filter.blockSignals(False)
        if selected:
            self._reselect(selected)
        elif rows and not self.table.selectionModel().selectedRows():
            self.table.selectRow(0)

    def _selected_key(self) -> tuple[str, str] | None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return None
        row = self.proxy.data(indexes[0], Qt.ItemDataRole.UserRole)
        if isinstance(row, dict):
            return (str(row.get("client")), str(row.get("server")))
        return None

    def _reselect(self, key: tuple[str, str]) -> None:
        for row_index in range(self.proxy.rowCount()):
            index = self.proxy.index(row_index, 0)
            row = self.proxy.data(index, Qt.ItemDataRole.UserRole)
            if isinstance(row, dict) and (str(row.get("client")), str(row.get("server"))) == key:
                self.table.selectRow(row_index)
                return

    def _on_select(self) -> None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        row = self.proxy.data(indexes[0], Qt.ItemDataRole.UserRole)
        if not isinstance(row, dict):
            return
        while self.detail_grid.count():
            item = self.detail_grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        rows = flow_detail_rows(row)
        for index, (key, value) in enumerate(rows):
            key_label = QLabel(key)
            key_label.setFixedWidth(78)
            key_label.setStyleSheet(f"color: {self.palette.text_faint}; font-size: 10.5px;")
            value_label = ElidedLabel(value)
            value_label.setObjectName("Mono")
            value_label.setStyleSheet("font-size: 11px;")
            self.detail_grid.addWidget(key_label, index // 4, (index % 4) * 2)
            self.detail_grid.addWidget(value_label, index // 4, (index % 4) * 2 + 1)

    def clear(self) -> None:
        self.model.clear()
        self.count_label.setText("0 条会话")


# --------------------------------------------------------------------------- packets
class PacketsPage(Page):
    title = "数据包"
    subtitle = "帧级视图：解码字段与十六进制"

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(palette, parent)
        self.model = PacketModel()
        self.proxy = RowFilterProxy()
        self.proxy.setSourceModel(self.model)
        self.table = _table(self.proxy, palette)
        self.table.setColumnWidth(0, 46)
        self.table.setColumnWidth(1, 72)
        self.table.setColumnWidth(2, 130)
        self.table.setColumnWidth(3, 130)
        self.table.setColumnWidth(4, 46)
        self.table.setColumnWidth(5, 42)
        self.table.setColumnWidth(7, 56)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.table.setItemDelegate(MonoDelegate((1, 2, 3, 4), size=10.0))
        self.table.selectionModel().selectionChanged.connect(self._on_select)
        self.table.viewport().installEventFilter(self)

        bar = _toolbar()
        self.search = QLineEdit()
        self.search.setPlaceholderText("按地址、端口、协议或摘要过滤帧…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.proxy.set_needle)
        bar.addWidget(self.search, 1)
        self.autoscroll = QCheckBox("跟随最新")
        self.autoscroll.setChecked(True)
        bar.addWidget(self.autoscroll)
        self.count_label = QLabel("0 帧")
        self.count_label.setObjectName("Faint")
        bar.addWidget(self.count_label)
        self.root.addLayout(bar)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        table_card = Card()
        table_card.add(self.table, 1)
        splitter.addWidget(table_card)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)
        self.fields = Card("解码字段", "协议栈与关键字段")
        self.fields_text = QPlainTextEdit()
        self.fields_text.setReadOnly(True)
        self.fields_text.setObjectName("Mono")
        self.fields_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        _left_align(self.fields_text)
        self.fields_text.setStyleSheet(
            f"background: {palette.elevated}; border: 1px solid {palette.border}; border-radius: 8px; padding: 8px;"
        )
        self.fields_text.setMinimumHeight(126)
        self.fields.add(self.fields_text, 1)
        # The field list is a fixed seven rows: cap it so the hexdump — the part
        # that grows — gets the remaining height instead of a dead panel.
        self.fields.setMaximumHeight(226)
        right_layout.addWidget(self.fields, 0)
        self.hex_card = Card("原始字节", "每帧最多显示 8 KiB")
        self.hex = HexView()
        self.hex_card.add(self.hex, 1)
        right_layout.addWidget(self.hex_card, 1)
        splitter.addWidget(right)
        splitter.setSizes([1080, 430])
        self.root.addWidget(splitter, 1)

    def _sync_columns(self) -> None:
        # On a narrow window the summary is the column that must survive: shed
        # the application and length columns before it gets squeezed to nothing.
        width = self.table.viewport().width()
        self.table.setColumnHidden(7, width < 680)
        self.table.setColumnHidden(5, width < 600)

    def eventFilter(self, watched: object, event: object) -> bool:  # noqa: N802
        if watched is self.table.viewport() and event.type() == QEvent.Type.Resize:  # type: ignore[attr-defined]
            self._sync_columns()
        return super().eventFilter(watched, event)  # type: ignore[arg-type]

    def add_packets(self, rows: list[tuple[object, ...]]) -> None:
        if not rows:
            return
        self.model.add_batch(rows)
        self.count_label.setText(f"{self.model.rowCount():,} 帧")
        if self.autoscroll.isChecked() and self.proxy.rowCount():
            self.table.scrollToBottom()
            if not self.table.selectionModel().selectedRows():
                self.table.selectRow(self.proxy.rowCount() - 1)

    def _on_select(self) -> None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        row = self.proxy.data(indexes[0], Qt.ItemDataRole.UserRole)
        if not isinstance(row, tuple) or len(row) < 9:
            return
        number, ts, src, dst, proto, length, info, app, raw = row
        lines = [
            f"帧号        {number}",
            f"时间        t+{ts}s",
            f"长度        {length} 字节（线上）",
            f"协议        {proto}{(' / ' + str(app)) if app else ''}",
            f"源          {src}",
            f"目的        {dst}",
            f"摘要        {info}",
        ]
        _set_mono_text(self.fields_text, "\n".join(lines))
        self.hex.show_bytes(bytes(raw))
        self.hex_card.hint_label.setText(f"帧长 {len(raw):,} 字节 · 最多显示 8 KiB")

    def clear(self) -> None:
        self.model.clear()
        self.count_label.setText("0 帧")
        self.fields_text.clear()
        self.hex.clear()


# --------------------------------------------------------------------------- media
class ArtifactPreview(QWidget):
    """Preview pane for a carved artifact: audio waveform or decoded image."""

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self._kind = ""
        self._pixmap: QPixmap | None = None
        self._peaks: list[float] = []
        self._progress = 0.0
        self.setStyleSheet("background: transparent;")
        self.setMinimumHeight(150)

    # ------------------------------------------------------------------ content
    def set_artifact(self, kind: str, data: bytes) -> None:
        self._kind = kind or ""
        self._pixmap = None
        self._peaks = []
        self._progress = 0.0
        if self._kind.startswith("audio/"):
            self._load_waveform(data)
        elif self._kind.startswith("image/"):
            pixmap = QPixmap()
            if pixmap.loadFromData(data):
                self._pixmap = pixmap
        self.update()

    def clear(self) -> None:
        self._kind = ""
        self._pixmap = None
        self._peaks = []
        self._progress = 0.0
        self.update()

    def set_progress(self, fraction: float) -> None:
        self._progress = max(0.0, min(1.0, float(fraction)))
        self.update()

    def _load_waveform(self, data: bytes) -> None:
        try:
            with wave.open(BytesIO(data), "rb") as handle:
                frames = handle.readframes(handle.getnframes())
                samples = array("h")
                samples.frombytes(frames[: len(frames) // 2 * 2])
        except (wave.Error, EOFError):
            return
        if not samples:
            return
        buckets = 320
        step = max(1, len(samples) // buckets)
        peaks = []
        for start in range(0, len(samples) - step + 1, step):
            chunk = samples[start : start + step]
            peaks.append(max(abs(min(chunk)), abs(max(chunk))) / 32768.0)
        self._peaks = peaks

    # ------------------------------------------------------------------ painting
    def paintEvent(self, event: object) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        palette = self._palette
        screen = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        painter.setPen(QPen(QColor(palette.border), 1))
        painter.setBrush(QColor(palette.bg))
        painter.drawRoundedRect(screen, 9, 9)
        inner = screen.adjusted(12, 10, -12, -10)

        if self._pixmap is not None and not self._pixmap.isNull():
            self._paint_image(painter, inner)
        elif self._peaks:
            self._paint_waveform(painter, inner)
        else:
            painter.setPen(QColor(palette.text_faint))
            painter.setFont(QFont(self.font().family(), 9))
            hint = "该产物没有可预览的音频或图像" if self._kind else "选择左侧的产物查看预览"
            painter.drawText(inner, Qt.AlignmentFlag.AlignCenter, hint)
        painter.end()

    def _paint_image(self, painter: QPainter, inner: QRectF) -> None:
        assert self._pixmap is not None
        target = QSize(max(1, int(inner.width())), max(1, int(inner.height())))
        scaled = self._pixmap.scaled(
            target, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
        )
        x = inner.center().x() - scaled.width() / 2
        y = inner.center().y() - scaled.height() / 2
        painter.drawPixmap(
            QRectF(x, y, scaled.width(), scaled.height()),
            scaled,
            QRectF(scaled.rect()),
        )
        painter.setPen(QColor(self._palette.text_faint))
        painter.setFont(QFont(self.font().family(), 8.5))
        painter.drawText(
            inner,
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom,
            f"{self._pixmap.width()} × {self._pixmap.height()} px",
        )

    def _paint_waveform(self, painter: QPainter, inner: QRectF) -> None:
        palette = self._palette
        mid = inner.center().y()
        half = inner.height() / 2 - 5
        accent = QColor(palette.accent)
        dim = QColor(accent)
        dim.setAlpha(105)
        gradient = QLinearGradient(inner.topLeft(), inner.bottomLeft())
        gradient.setColorAt(0.0, accent)
        gradient.setColorAt(1.0, QColor(palette.accent).darker(155))

        slot = inner.width() / len(self._peaks)
        bar = max(1.0, min(4.0, slot - 0.8))
        played = int(self._progress * len(self._peaks))
        live = QBrush(gradient) if 0.0 < self._progress < 1.0 else QBrush(accent)
        painter.setPen(Qt.PenStyle.NoPen)
        for index, peak in enumerate(self._peaks):
            if peak <= 0.002:
                continue  # silence stays silent: no dotted centre line
            height = max(1.0, peak * half)
            x = inner.left() + index * slot
            painter.setBrush(live if index < played or self._progress <= 0.0 else dim)
            painter.drawRoundedRect(QRectF(x, mid - height, bar, height * 2), 1, 1)

        if 0.0 < self._progress < 1.0:
            x = inner.left() + inner.width() * self._progress
            painter.setPen(QPen(QColor(palette.text), 1.2))
            painter.drawLine(QPointF(x, inner.top() + 2), QPointF(x, inner.bottom() - 2))


class MediaPage(Page):
    title = "媒体"
    subtitle = "从流量中还原的载荷与重建的语音"

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(palette, parent)
        self.model = ArtifactModel()
        self.proxy = RowFilterProxy()
        self.proxy.setSourceModel(self.model)
        self.table = _table(self.proxy, palette)
        self.table.setColumnWidth(0, 120)
        self.table.setColumnWidth(1, 320)
        self.table.setColumnWidth(2, 88)
        self.table.setColumnWidth(3, 140)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setItemDelegate(MonoDelegate((1,), size=10.0))
        self.table.selectionModel().selectionChanged.connect(self._on_select)

        bar = _toolbar()
        self.search = QLineEdit()
        self.search.setPlaceholderText("按文件名、类型或哈希过滤产物…")
        self.search.textChanged.connect(self.proxy.set_needle)
        self.search.setClearButtonEnabled(True)
        bar.addWidget(self.search, 1)
        self.save_button = QPushButton("导出所选…")
        self.save_button.clicked.connect(self._save_selected)
        self.save_button.setEnabled(False)
        bar.addWidget(self.save_button)
        self.count_label = QLabel("0 个产物")
        self.count_label.setObjectName("Faint")
        bar.addWidget(self.count_label)
        self.root.addLayout(bar)

        splitter = QSplitter(Qt.Orientation.Vertical)
        table_card = Card()
        table_card.add(self.table, 1)
        splitter.addWidget(table_card)

        preview_card = Card("预览", "语音还原为波形，图片按原图显示；导出后可离线查看")
        self.preview = ArtifactPreview(palette)
        preview_card.add(self.preview, 1)

        transport = QHBoxLayout()
        transport.setSpacing(10)
        self.play_button = QPushButton("播放")
        self.play_button.setObjectName("Ghost")
        self.play_button.setFixedWidth(72)
        self.play_button.setEnabled(False)
        self.play_button.clicked.connect(self._toggle_play)
        transport.addWidget(self.play_button)
        self.position_label = QLabel("0:00.0 / 0:00.0")
        self.position_label.setObjectName("Mono")
        self.position_label.setStyleSheet(f"color: {palette.text_faint}; font-size: 10.5px;")
        transport.addWidget(self.position_label)
        transport.addStretch(1)
        hint = QLabel("G.711 µ-law / A-law → PCM → WAV")
        hint.setObjectName("Faint")
        hint.setStyleSheet("font-size: 10.5px;")
        transport.addWidget(hint)
        preview_card.add_layout(transport)

        meta = QGridLayout()
        meta.setHorizontalSpacing(10)
        meta.setVerticalSpacing(6)
        self.meta_fields: dict[str, QLabel] = {}
        keys = ("类型", "大小", "编码", "采样率", "时长", "丢包", "来源")
        for index, key in enumerate(keys):
            column = index % 4
            row = index // 4
            label = QLabel(key)
            label.setStyleSheet(f"color: {palette.text_faint}; font-size: 10.5px;")
            label.setFixedWidth(40)
            value = QLabel("—")
            value.setObjectName("Mono")
            value.setStyleSheet("font-size: 10.5px;")
            meta.addWidget(label, row, column * 2)
            meta.addWidget(value, row, column * 2 + 1)
            meta.setColumnStretch(column * 2 + 1, 1)
            self.meta_fields[key] = value
        hash_label = QLabel("SHA-256")
        hash_label.setStyleSheet(f"color: {palette.text_faint}; font-size: 10.5px;")
        hash_label.setFixedWidth(52)
        self.hash_value = ElidedLabel("—")
        self.hash_value.setObjectName("Mono")
        self.hash_value.setStyleSheet("font-size: 10.5px;")
        self.copy_button = QPushButton("复制")
        self.copy_button.setObjectName("Ghost")
        self.copy_button.setFixedWidth(56)
        self.copy_button.clicked.connect(self._copy_hash)
        meta.addWidget(hash_label, 2, 0)
        meta.addWidget(self.hash_value, 2, 1, 1, 6)
        meta.addWidget(self.copy_button, 2, 7)
        preview_card.add_layout(meta)
        splitter.addWidget(preview_card)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([276, 520])
        self.root.addWidget(splitter, 1)

        self._current: dict[str, object] | None = None
        self._sink: object | None = None
        self._audio_io: object | None = None
        self._audio_api: object | None = None
        self._pcm = b""
        self._pcm_offset = 0
        self._duration_ms = 0.0
        self._finished = False
        self._audio_timer = QTimer(self)
        self._audio_timer.setInterval(60)
        self._audio_timer.timeout.connect(self._pump_audio)

    # ------------------------------------------------------------------ data
    def add_artifacts(self, rows: list[dict[str, object]]) -> None:
        self.model.add_rows(rows)
        self.count_label.setText(f"{self.model.rowCount():,} 个产物")
        if not self.table.selectionModel().selectedRows():
            self._select_best()

    def _select_best(self) -> None:
        """Prefer an audio artifact: the waveform is the interesting part."""
        target = 0
        for index in range(self.proxy.rowCount()):
            row = self.proxy.data(self.proxy.index(index, 0), Qt.ItemDataRole.UserRole)
            if isinstance(row, dict) and str(row.get("kind", "")).startswith("audio/"):
                target = index
                break
        if self.proxy.rowCount():
            self.table.selectRow(target)

    def _on_select(self) -> None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        row = self.proxy.data(indexes[0], Qt.ItemDataRole.UserRole)
        if not isinstance(row, dict):
            return
        self._stop_playback()
        self._current = row
        self.save_button.setEnabled(True)
        artifact = row.get("_object")
        data = getattr(artifact, "data", b"")
        kind = str(row.get("kind") or "")
        self.preview.set_artifact(kind, data)
        self.play_button.setEnabled(kind.startswith("audio/") and bool(data))
        self._fill_meta(row, kind)

    def _fill_meta(self, row: dict[str, object], kind: str) -> None:
        meta = row.get("meta") if isinstance(row.get("meta"), dict) else {}
        assert isinstance(meta, dict)
        duration = float(meta.get("duration_s") or 0.0)
        values = {
            "类型": kind or "—",
            "大小": human_bytes(int(row.get("size", 0) or 0)),
            "编码": str(meta.get("codec") or "—"),
            "采样率": f"{int(meta['sample_rate']):,} Hz" if meta.get("sample_rate") else "—",
            "时长": f"{duration:.2f} 秒" if duration else "—",
            "丢包": f"{float(meta['loss_percent']):.1f}%" if meta.get("loss_percent") is not None else "—",
            "来源": {"rtp": "RTP 通话", "http": "HTTP 响应", "tls": "TLS 流"}.get(
                str(row.get("source") or ""), str(row.get("source") or "—")
            ),
        }
        for key, value in values.items():
            self.meta_fields[key].setText(value)
        digest = str(row.get("sha256") or "—")
        self.hash_value.setText(digest)
        self.hash_value.setToolTip(digest)
        self.position_label.setText(f"0:00.0 / {_mmss(duration * 1000)}" if duration else "0:00.0 / 0:00.0")

    def _copy_hash(self) -> None:
        from PySide6.QtGui import QGuiApplication

        digest = str((self._current or {}).get("sha256") or "")
        if digest:
            QGuiApplication.clipboard().setText(digest)
            self.copy_button.setText("已复制")
            QTimer.singleShot(1200, lambda: self.copy_button.setText("复制"))

    # ------------------------------------------------------------------ playback
    #
    # QMediaPlayer needs a demuxer plugin that many pip installs of PySide6 do
    # not ship. The reconstructed call is already bare PCM in a WAV container,
    # so QAudioSink — which only needs the platform audio backend — plays it
    # directly, with no temp files and no codec dependency.

    def _ensure_sink(self) -> bool:
        if self._sink is not None:
            return True
        try:
            from PySide6.QtMultimedia import QAudio, QAudioFormat, QAudioSink, QMediaDevices
        except ImportError:
            return False
        self._audio_api = QAudio
        artifact = (self._current or {}).get("_object")
        data = getattr(artifact, "data", b"")
        try:
            with wave.open(BytesIO(data), "rb") as handle:
                channels = handle.getnchannels()
                width = handle.getsampwidth()
                rate = handle.getframerate()
                frames = handle.readframes(handle.getnframes())
        except (wave.Error, EOFError):
            return False
        sample_format = {
            1: QAudioFormat.SampleFormat.UInt8,
            2: QAudioFormat.SampleFormat.Int16,
            4: QAudioFormat.SampleFormat.Int32,
        }.get(width, QAudioFormat.SampleFormat.Unknown)
        if sample_format == QAudioFormat.SampleFormat.Unknown or rate <= 0 or not frames:
            return False
        fmt = QAudioFormat()
        fmt.setSampleRate(rate)
        fmt.setChannelCount(channels)
        fmt.setSampleFormat(sample_format)
        device = QMediaDevices.defaultAudioOutput()
        if device.isNull() or not device.isFormatSupported(fmt):
            return False
        sink = QAudioSink(device, fmt, self)
        sink.stateChanged.connect(self._on_sink_state)
        audio_io = sink.start()
        if audio_io is None:
            sink.deleteLater()
            return False
        self._pcm = frames
        self._pcm_offset = 0
        self._duration_ms = len(frames) / max(1, channels * width) / rate * 1000.0
        self._finished = False
        self._sink = sink
        self._audio_io = audio_io
        self._audio_timer.start()
        self._pump_audio()
        return True

    def _pump_audio(self) -> None:
        sink = self._sink
        audio_io = self._audio_io
        if sink is None or audio_io is None:
            return
        if self._pcm_offset < len(self._pcm):
            chunk = self._pcm[self._pcm_offset : self._pcm_offset + 8192]
            written = audio_io.write(chunk)
            if written and written > 0:
                self._pcm_offset += written
            state = sink.state()
            if (
                self._audio_api is not None
                and state == self._audio_api.State.IdleState
                and self._pcm_offset < len(self._pcm)
            ):
                sink.resume()
        self._update_position()

    def _update_position(self) -> None:
        sink = self._sink
        if sink is None or self._duration_ms <= 0:
            return
        elapsed = min(float(sink.processedUSecs()) / 1000.0, self._duration_ms)
        self.preview.set_progress(elapsed / self._duration_ms)
        self.position_label.setText(f"{_mmss(elapsed)} / {_mmss(self._duration_ms)}")
        if elapsed >= self._duration_ms - 20 and self._pcm_offset >= len(self._pcm):
            self._finish_playback()

    def _finish_playback(self) -> None:
        if self._finished:
            return
        self._finished = True
        self._audio_timer.stop()
        self.preview.set_progress(1.0)
        self.position_label.setText(f"{_mmss(self._duration_ms)} / {_mmss(self._duration_ms)}")
        self.play_button.setText("重播")

    def _toggle_play(self) -> None:
        if self._current is None:
            return
        if self._sink is None:
            if not self._ensure_sink():
                QMessageBox.information(
                    self,
                    "无法试听",
                    "当前环境没有可用的音频输出或 QtMultimedia 组件。\n产物已可导出，可用系统播放器打开。",
                )
                return
            self.play_button.setText("暂停")
            return
        sink = self._sink
        assert sink is not None
        if self._finished:
            sink.stop()
            self._sink = None
            self._audio_io = None
            self._finished = False
            self.play_button.setText("播放")
            self.preview.set_progress(0.0)
            if self._ensure_sink():
                self.play_button.setText("暂停")
            return
        api = self._audio_api
        state = sink.state()
        if api is not None and state == api.State.ActiveState:
            sink.suspend()
            self.play_button.setText("继续")
            return
        if api is not None and state == api.State.SuspendedState:
            sink.resume()
            self.play_button.setText("暂停")
            if self._audio_timer.isActive() is False:
                self._audio_timer.start()
            return
        sink.resume()
        self._audio_timer.start()
        self._pump_audio()
        self.play_button.setText("暂停")

    def _on_sink_state(self, state: object) -> None:
        api = self._audio_api
        if api is not None and state == api.State.IdleState and self._pcm_offset < len(self._pcm):
            # buffer drained mid-clip: keep feeding it
            self._pump_audio()

    def _stop_playback(self) -> None:
        self._audio_timer.stop()
        if self._sink is not None:
            with contextlib.suppress(RuntimeError):
                self._sink.stop()
                self._sink.deleteLater()
        self._sink = None
        self._audio_io = None
        self._pcm = b""
        self._pcm_offset = 0
        self._finished = False
        self.preview.set_progress(0.0)
        self.play_button.setText("播放")
        meta = (self._current or {}).get("meta") if isinstance(self._current, dict) else None
        duration = float(meta.get("duration_s") or 0.0) if isinstance(meta, dict) else 0.0
        self.position_label.setText(f"0:00.0 / {_mmss(duration * 1000)}" if duration else "0:00.0 / 0:00.0")

    # ------------------------------------------------------------------ export
    def _save_selected(self) -> None:
        artifact = (self._current or {}).get("_object")
        if artifact is None or not hasattr(artifact, "data"):
            return
        suggested = str(getattr(artifact, "name", "artifact.bin"))
        path, _ = QFileDialog.getSaveFileName(self, "导出产物", suggested)
        if not path:
            return
        with open(path, "wb") as handle:
            handle.write(artifact.data)
        QMessageBox.information(self, "已保存", f"已写入 {path}")

    def clear(self) -> None:
        self._stop_playback()
        self.model.clear()
        self.count_label.setText("0 个产物")
        self.preview.clear()
        self.play_button.setEnabled(False)
        self.position_label.setText("0:00.0 / 0:00.0")
        for label in self.meta_fields.values():
            label.setText("—")
        self.hash_value.setText("—")


def _mmss(milliseconds: float) -> str:
    """``m:ss.d`` under a minute (clips are short), ``mm:ss`` above it."""
    seconds = max(0.0, milliseconds / 1000.0)
    if seconds < 60:
        return f"{int(seconds // 60)}:{seconds % 60:04.1f}"
    return f"{int(seconds // 60):02d}:{int(seconds % 60):02d}"


# --------------------------------------------------------------------------- alerts
class AlertsPage(Page):
    title = "发现"
    subtitle = "规则命中与行为检测，按严重程度排序"

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(palette, parent)
        self.model = AlertModel()
        self.proxy = RowFilterProxy()
        self.proxy.setSourceModel(self.model)
        self.table = _table(self.proxy, palette)
        self.table.setColumnWidth(0, 72)
        self.table.setColumnWidth(1, 84)
        self.table.setColumnWidth(2, 360)
        self.table.setColumnWidth(3, 180)
        self.table.setColumnWidth(4, 220)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setItemDelegate(MonoDelegate((4,), size=10.0))
        self.table.setItemDelegateForColumn(1, SeverityDelegate(palette, 1))
        self.table.selectionModel().selectionChanged.connect(self._on_select)

        bar = _toolbar()
        self.search = QLineEdit()
        self.search.setPlaceholderText("过滤发现…")
        self.search.textChanged.connect(self.proxy.set_needle)
        self.search.setClearButtonEnabled(True)
        bar.addWidget(self.search, 1)
        self.count_label = QLabel("0 条发现")
        self.count_label.setObjectName("Faint")
        bar.addWidget(self.count_label)
        self.root.addLayout(bar)

        splitter = QSplitter(Qt.Orientation.Vertical)
        table_card = Card()
        table_card.add(self.table, 1)
        splitter.addWidget(table_card)
        self.detail = Card("证据", "规则依据与触发它的数据")
        self.detail_text = QPlainTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setObjectName("Mono")
        self.detail_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        _left_align(self.detail_text)
        self.detail_text.setStyleSheet(
            f"background: {palette.elevated}; border: 1px solid {palette.border}; border-radius: 8px; padding: 8px;"
        )
        self.detail.add(self.detail_text, 1)
        splitter.addWidget(self.detail)
        splitter.setSizes([420, 300])
        self.root.addWidget(splitter, 1)

    def add_alerts(self, rows: list[dict[str, object]]) -> None:
        combined = self.model.rows() + list(rows)
        combined.sort(key=lambda row: (-int(row.get("severity", 0)), -float(row.get("ts", 0) or 0)))
        self.model.reset_rows(combined)
        self.count_label.setText(f"{self.model.rowCount():,} 条发现")
        if not self.table.selectionModel().selectedRows() and self.proxy.rowCount():
            self.table.selectRow(0)

    def _on_select(self) -> None:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        row = self.proxy.data(indexes[0], Qt.ItemDataRole.UserRole)
        if not isinstance(row, dict):
            return
        evidence = json.dumps(row.get("evidence") or {}, indent=2, ensure_ascii=False, default=str)
        lines = [
            str(row.get("title", "")),
            "",
            _pad("严重程度") + severity_label(int(row.get("severity", 0))),
            _pad("规则") + str(row.get("rule", "")),
            _pad("端点") + str(row.get("flow", "")),
        ]
        description = str(row.get("description") or "").strip()
        if description:
            lines += ["", description]
        lines += ["", "附加字段", evidence if evidence.strip() not in ("{}", "null") else "（无）"]
        _set_mono_text(self.detail_text, "\n".join(lines))

    def clear(self) -> None:
        self.model.clear()
        self.count_label.setText("0 条发现")
        self.detail_text.clear()


# --------------------------------------------------------------------------- settings
class SettingsPage(Page):
    title = "设置"
    subtitle = "抓包参数、检测规则与版本信息"

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(palette, parent)

        top = QHBoxLayout()
        top.setSpacing(12)

        capture_card = Card("抓包", "修改后在下一次在线抓包时生效")
        form = QGridLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(10)
        form.setColumnMinimumWidth(0, 64)
        form.setColumnStretch(1, 1)
        form.setColumnStretch(3, 1)

        self.interface = QComboBox()
        self.interface.setMinimumWidth(300)
        self.refresh_interfaces()
        refresh = QPushButton("重新扫描")
        refresh.setFixedWidth(86)
        refresh.clicked.connect(self.refresh_interfaces)
        form.addWidget(QLabel("网卡"), 0, 0)
        iface_row = QHBoxLayout()
        iface_row.setSpacing(8)
        iface_row.addWidget(self.interface, 1)
        iface_row.addWidget(refresh)
        form.addLayout(iface_row, 0, 1, 1, 4)

        self.snaplen = QSpinBox()
        self.snaplen.setRange(64, 262144)
        self.snaplen.setValue(262144)
        self.snaplen.setSingleStep(1024)
        form.addWidget(QLabel("截断长度"), 1, 0)
        form.addWidget(self.snaplen, 1, 1)

        self.buffer = QSpinBox()
        self.buffer.setRange(1, 512)
        self.buffer.setValue(16)
        self.buffer.setSuffix(" MB")
        form.addWidget(QLabel("内核缓冲"), 1, 2)
        form.addWidget(self.buffer, 1, 3)

        self.promisc = QCheckBox("请求混杂模式（promisc）")
        self.promisc.setChecked(True)
        form.addWidget(self.promisc, 2, 0, 1, 2)
        self.checksums = QCheckBox("校验 IP/TCP/UDP 校验和")
        form.addWidget(self.checksums, 2, 2, 1, 3)
        capture_card.add_layout(form)
        top.addWidget(capture_card, 3)

        about = Card("关于", "版本来源与合法使用范围")
        about_grid = QGridLayout()
        about_grid.setHorizontalSpacing(12)
        about_grid.setVerticalSpacing(7)
        about_grid.setColumnStretch(1, 1)
        self.about_rules = QLabel("—")
        rows: tuple[tuple[str, str | None], ...] = (
            ("版本", f"VoxHound {__version__}"),
            ("许可", "MIT"),
            ("规则集", None),
            ("抓包后端", capture_backend_short()),
        )
        for index, (key, value) in enumerate(rows):
            key_label = QLabel(key)
            key_label.setStyleSheet(f"color: {palette.text_faint}; font-size: 10.5px;")
            key_label.setFixedWidth(62)
            about_grid.addWidget(key_label, index, 0)
            value_label = self.about_rules if value is None else QLabel(value)
            value_label.setObjectName("Mono")
            value_label.setStyleSheet("font-size: 11px;")
            value_label.setWordWrap(True)
            if key == "抓包后端":
                value_label.setToolTip(f"{capture_backend_hint()}\n{capture_backend()}")
            about_grid.addWidget(value_label, index, 1)
        about.add_layout(about_grid)
        legal = QLabel(
            "只读取帧、不注入数据包；只解析握手、不做中间人。\n"
            "仅可用于你拥有或已获授权的网络。抓包内容可能包含个人数据。"
        )
        legal.setObjectName("Faint")
        legal.setWordWrap(True)
        legal.setStyleSheet("font-size: 10.5px;")
        # Chinese has no spaces: without an ignored width policy the wrap label
        # reports a huge minimum and overflows the card on narrow windows.
        legal.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        about.add(legal)
        top.addWidget(about, 2)
        self.root.addLayout(top)

        rules_card = Card("检测规则", "内置 JSON 规则；可用 --rules 追加自己的规则目录")
        self.rules_model = RuleModel()
        self.rules_table = _table(self.rules_model, palette)
        self.rules_table.setColumnWidth(0, 232)
        self.rules_table.setColumnWidth(2, 200)
        self.rules_table.setColumnWidth(3, 84)
        self.rules_table.setColumnWidth(4, 70)
        self.rules_table.setColumnWidth(5, 56)
        self.rules_table.setColumnWidth(6, 100)
        self.rules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.rules_table.setItemDelegateForColumn(3, SeverityDelegate(palette, 3))
        rules_card.add(self.rules_table, 1)
        self.root.addWidget(rules_card, 1)

    def refresh_interfaces(self) -> None:
        current = self.interface.currentText() if self.interface.count() else ""
        self.interface.clear()
        for iface in list_interfaces():
            self.interface.addItem(iface.description or iface.name, iface.name)
            self.interface.setItemData(self.interface.count() - 1, iface.name, Qt.ItemDataRole.ToolTipRole)
        if current:
            index = self.interface.findText(current)
            if index >= 0:
                self.interface.setCurrentIndex(index)

    def set_rules(self, rows: list[dict[str, object]]) -> None:
        self.rules_model.reset_rows(rows)
        self.about_rules.setText(f"{len(rows)} 条内置规则")

    def capture_options(self) -> dict[str, object]:
        return {
            "interface": self.interface.currentData(),
            "snaplen": self.snaplen.value(),
            "buffer_mb": self.buffer.value(),
            "promisc": self.promisc.isChecked(),
            "verify_checksums": self.checksums.isChecked(),
        }

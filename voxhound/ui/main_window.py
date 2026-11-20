"""Application shell: sidebar navigation, capture bar, status strip.

Wiring philosophy: the window owns the models, the controller owns the thread,
the pages own nothing but their own widgets. One ``QTimer`` drives the clock;
everything else is event-driven off the controller's signals.
"""

from __future__ import annotations

import os
import time
from collections import Counter
from typing import Any

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QAction, QColor, QKeySequence, QPainter, QShortcut
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from ..capture.interfaces import default_interface, list_interfaces
from ..core.util import human_duration
from ..flows.table import endpoint
from .controller import CaptureController
from .pages import AlertsPage, DashboardPage, FlowsPage, MediaPage, PacketsPage, SettingsPage
from .theme import DARK, Palette, qss, tint
from .widgets import RatePill

NAV_ITEMS = (
    ("dashboard", "仪表盘"),
    ("flows", "会话"),
    ("packets", "数据包"),
    ("media", "媒体"),
    ("alerts", "发现"),
    ("settings", "设置"),
)


class StatusDot(QWidget):
    """Small pulsing dot; green while capturing, grey when idle."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._on = False
        self.setFixedSize(QSize(10, 10))

    def set_active(self, active: bool) -> None:
        self._on = active
        self.update()

    def paintEvent(self, event: object) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#2FD3A5" if self._on else "#3A4761"))
        painter.drawEllipse(1, 1, 8, 8)
        painter.end()


class MainWindow(QMainWindow):
    def __init__(self, palette: Palette = DARK, *, spec: str | None = None, filter_expr: str = "") -> None:
        super().__init__()
        self.palette_tokens = palette
        self.setWindowTitle(f"VoxHound {__version__} —— 被动网络取证工作台")
        self.resize(1500, 940)
        self.setMinimumSize(1120, 720)
        self.setStyleSheet(qss(palette))

        self.controller = CaptureController(self)
        self._last_snapshot: dict[str, Any] = {}
        self._started_at = 0.0
        self._capture_spec = spec or "demo"
        self._file_path: str | None = None

        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._build_sidebar())

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        right_layout.addWidget(self._build_topbar())
        self.stack = QStackedWidget()
        self.dashboard = DashboardPage(palette)
        self.flows_page = FlowsPage(palette)
        self.packets_page = PacketsPage(palette)
        self.media_page = MediaPage(palette)
        self.alerts_page = AlertsPage(palette)
        self.settings_page = SettingsPage(palette)
        self.pages = {
            "dashboard": self.dashboard,
            "flows": self.flows_page,
            "packets": self.packets_page,
            "media": self.media_page,
            "alerts": self.alerts_page,
            "settings": self.settings_page,
        }
        for page in self.pages.values():
            self.stack.addWidget(page)
        right_layout.addWidget(self.stack, 1)
        layout.addWidget(right, 1)
        self.setCentralWidget(central)

        self._build_statusbar()
        self._connect()
        self._set_page("dashboard")
        self.settings_page.set_rules(self._rule_rows())

        self._clock = QTimer(self)
        self._clock.setInterval(400)
        self._clock.timeout.connect(self._tick)
        self._clock.start()

        self._install_shortcuts()
        self._apply_initial_spec()
        if filter_expr:
            self.filter_input.setText(filter_expr)

    # ------------------------------------------------------------------ chrome
    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(206)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(14, 18, 14, 14)
        layout.setSpacing(4)

        brand = QLabel("VOXHOUND")
        brand.setObjectName("SidebarBrand")
        layout.addWidget(brand)
        version = QLabel(f"v{__version__} · 取证控制台")
        version.setObjectName("SidebarVersion")
        layout.addWidget(version)
        layout.addSpacing(18)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_buttons: dict[str, QPushButton] = {}
        for key, label in NAV_ITEMS:
            button = QPushButton(label)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(lambda _checked=False, k=key: self._set_page(k))
            self.nav_group.addButton(button)
            layout.addWidget(button)
            self.nav_buttons[key] = button
        layout.addStretch(1)

        self.sidebar_badge = QLabel("空闲")
        self.sidebar_badge.setObjectName("SidebarVersion")
        self.sidebar_dot = StatusDot()
        row = QHBoxLayout()
        row.setSpacing(7)
        row.addWidget(self.sidebar_dot)
        row.addWidget(self.sidebar_badge)
        row.addStretch(1)
        layout.addLayout(row)
        layout.addSpacing(6)

        hint = QLabel("全程被动抓包。\n仅限自有或已授权网络。")
        hint.setObjectName("SidebarHint")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        return sidebar

    def _build_topbar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("TopBar")
        bar.setFixedHeight(62)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(18, 8, 18, 8)
        layout.setSpacing(10)

        titles = QVBoxLayout()
        titles.setSpacing(0)
        self.title_label = QLabel("仪表盘")
        self.title_label.setObjectName("PageTitle")
        self.subtitle_label = QLabel("")
        self.subtitle_label.setObjectName("PageSubtitle")
        titles.addWidget(self.title_label)
        titles.addWidget(self.subtitle_label)
        layout.addLayout(titles)
        layout.addStretch(1)

        self.source_combo = QComboBox()
        self.source_combo.setMinimumWidth(190)
        self._fill_sources()
        self.source_combo.currentIndexChanged.connect(self._on_source_changed)
        layout.addWidget(self.source_combo)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("BPF 过滤，如 tcp port 443")
        self.filter_input.setToolTip("抓包/分析过滤表达式，支持 host、port、portrange、tcp/udp 与 and/or/not")
        self.filter_input.setMinimumWidth(200)
        self.filter_input.setMaximumWidth(280)
        layout.addWidget(self.filter_input)

        self.start_button = QPushButton("开始抓包")
        self.start_button.setToolTip("开始一次新会话（Ctrl+R）")
        self.start_button.setObjectName("Primary")
        self.start_button.clicked.connect(self.start_capture)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton("停止")
        self.stop_button.setObjectName("Ghost")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.controller.stop)
        layout.addWidget(self.stop_button)

        self.save_button = QPushButton("保存报告")
        self.save_button.setToolTip("把本次会话写成自包含 HTML 报告（Ctrl+S）")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_report)
        layout.addWidget(self.save_button)
        return bar

    def _build_statusbar(self) -> None:
        status = self.statusBar()
        status.setSizeGripEnabled(False)
        self.pps_pill = RatePill("0 包/秒", self.palette_tokens.info)
        self.flows_pill = RatePill("0 会话", self.palette_tokens.accent)
        self.findings_pill = RatePill("0 发现", self.palette_tokens.danger)
        self.elapsed_label = QLabel("00:00")
        self.elapsed_label.setObjectName("Mono")
        self.source_label = QLabel("就绪")
        self.source_label.setObjectName("Faint")
        status.addWidget(self.source_label, 1)
        status.addPermanentWidget(self.elapsed_label)
        status.addPermanentWidget(self.pps_pill)
        status.addPermanentWidget(self.flows_pill)
        status.addPermanentWidget(self.findings_pill)

    # ------------------------------------------------------------------ wiring
    def _connect(self) -> None:
        self.controller.packets.connect(self._on_packets)
        self.controller.events.connect(self._on_events)
        self.controller.alerts.connect(self._on_alerts)
        self.controller.artifacts.connect(self._on_artifacts)
        self.controller.flows.connect(self._on_flows)
        self.controller.stats.connect(self._on_stats)
        self.controller.log.connect(self._on_log)
        self.controller.failed.connect(self._on_failed)
        self.controller.finished.connect(self._on_finished)
        self.controller.running_changed.connect(self._on_running_changed)

    def _install_shortcuts(self) -> None:
        for index, (key, _label) in enumerate(NAV_ITEMS, start=1):
            shortcut = QShortcut(QKeySequence(f"Ctrl+{index}"), self)
            shortcut.activated.connect(lambda k=key: self._set_page(k))
        toggle = QAction(self)
        toggle.setShortcut(QKeySequence("Ctrl+R"))
        toggle.triggered.connect(self._toggle_capture)
        self.addAction(toggle)
        save = QAction(self)
        save.setShortcut(QKeySequence("Ctrl+S"))
        save.triggered.connect(self.save_report)
        self.addAction(save)

    # ------------------------------------------------------------------ sources
    def _fill_sources(self) -> None:
        self.source_combo.blockSignals(True)
        self.source_combo.clear()
        self.source_combo.addItem("模拟流量（演示）", "demo")
        active = default_interface()
        for iface in list_interfaces():
            label = f"网卡 · {iface.description or iface.name}"
            if iface.name == active:
                label += "（默认）"
            self.source_combo.addItem(label, f"iface:{iface.name}")
            self.source_combo.setItemData(
                self.source_combo.count() - 1, iface.name, Qt.ItemDataRole.ToolTipRole
            )
        self.source_combo.addItem("打开抓包文件…", "__file__")
        self.source_combo.blockSignals(False)

    def _apply_initial_spec(self) -> None:
        """Preselect the file/interface passed to ``voxhound gui``.

        The combo's file entry normally opens a dialog, so this path sets the
        text directly with signals blocked instead of pretending a user click.
        """
        spec = str(self._capture_spec or "demo").strip()
        if spec in ("", "demo"):
            return
        if spec.startswith("iface:"):
            index = self.source_combo.findData(spec)
            if index < 0:
                self.source_combo.addItem(f"网卡 · {spec.split(':', 1)[1]}", spec)
                index = self.source_combo.count() - 1
            self.source_combo.setCurrentIndex(index)
            return
        path = spec[5:] if spec.startswith("file:") else spec
        if not os.path.isfile(path):
            return
        path = os.path.abspath(path)
        self._file_path = path
        self._capture_spec = f"file:{path}"
        index = self.source_combo.findData("__file__")
        if index >= 0:
            self.source_combo.blockSignals(True)
            self.source_combo.setItemText(index, f"文件 · {os.path.basename(path)}")
            self.source_combo.setCurrentIndex(index)
            self.source_combo.blockSignals(False)
        self.source_label.setText(f"就绪 · {os.path.basename(path)}")

    def _on_source_changed(self) -> None:
        data = str(self.source_combo.currentData() or "demo")
        if data == "__file__":
            path, _ = QFileDialog.getOpenFileName(
                self, "打开抓包文件", "", "抓包文件 (*.pcap *.pcapng *.cap *.gz);;所有文件 (*)"
            )
            if not path:
                self.source_combo.setCurrentIndex(0)
                return
            self._file_path = path
            self.source_combo.setItemText(
                self.source_combo.currentIndex(), f"文件 · {os.path.basename(path)}"
            )
            self._capture_spec = f"file:{path}"
        else:
            self._capture_spec = data

    def _current_spec(self) -> str:
        data = str(self.source_combo.currentData() or "demo")
        if data == "__file__":
            return f"file:{self._file_path}" if self._file_path else "demo"
        return data

    # ------------------------------------------------------------------ actions
    def start_capture(self) -> None:
        if self.controller.running:
            return
        self._clear_views()
        spec = self._current_spec()
        options = self.settings_page.capture_options()
        source_kwargs: dict[str, Any] = {}
        if spec.startswith("iface:"):
            source_kwargs = {
                "snaplen": int(options.get("snaplen", 262144)),
                "promisc": bool(options.get("promisc", True)),
                "buffer_mb": int(options.get("buffer_mb", 16)),
                "bpf": self.filter_input.text().strip(),
            }
        self._started_at = time.time()
        self.source_label.setText(f"抓包中 · {spec}")
        self.controller.start(
            spec,
            filter_expr=self.filter_input.text().strip(),
            options={
                "verify_checksums": bool(options.get("verify_checksums", False)),
                "source_kwargs": source_kwargs,
            },
        )

    def _toggle_capture(self) -> None:
        if self.controller.running:
            self.controller.stop()
        else:
            self.start_capture()

    def save_report(self) -> None:
        report = self.controller.report
        if report is None:
            QMessageBox.information(self, "暂无可保存内容", "请先运行一次抓包——报告会在会话结束时生成。")
            return
        default = f"voxhound-{time.strftime('%Y%m%d-%H%M%S')}.html"
        path, _ = QFileDialog.getSaveFileName(self, "保存报告", default, "HTML 报告 (*.html)")
        if not path:
            return
        try:
            written = self.controller.save_report(path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "报告生成失败", str(exc))
            return
        self.statusBar().showMessage(f"报告已写入 {written}", 8000)

    # ------------------------------------------------------------------ slots
    def _set_page(self, key: str) -> None:
        page = self.pages[key]
        self.stack.setCurrentWidget(page)
        self.title_label.setText(getattr(page, "title", key))
        self.subtitle_label.setText(getattr(page, "subtitle", ""))
        for nav_key, button in self.nav_buttons.items():
            button.setChecked(nav_key == key)

    def _on_packets(self, rows: list[tuple[Any, ...]]) -> None:
        self.packets_page.add_packets(rows)

    def _on_events(self, rows: list[dict[str, Any]]) -> None:
        if rows:
            latest = rows[-1]
            self.source_label.setText(str(latest.get("title") or latest.get("kind") or "")[:110])

    def _on_alerts(self, rows: list[dict[str, Any]]) -> None:
        self.alerts_page.add_alerts(rows)
        self.dashboard.add_alerts(rows)

    def _on_artifacts(self, rows: list[dict[str, Any]]) -> None:
        self.media_page.add_artifacts(rows)

    def _on_flows(self, rows: list[dict[str, Any]]) -> None:
        self.flows_page.refresh(rows)

    def _on_stats(self, snapshot: dict[str, Any]) -> None:
        self._last_snapshot = snapshot
        self.dashboard.update_stats(snapshot)
        self.pps_pill.setText(f"{float(snapshot.get('pps', 0)):,.0f} 包/秒")
        self.flows_pill.setText(f"{int(snapshot.get('flows', 0)):,} 会话")
        findings = int(snapshot.get("alerts", 0))
        self.findings_pill.setText(f"{findings:,} 发现")
        danger = self.palette_tokens.danger
        self.findings_pill.setStyleSheet(
            f"background: {tint(danger, 0.13)}; color: {danger};"
            f"border: 1px solid {tint(danger, 0.30)}; border-radius: 9px;"
            "padding: 2px 9px; font-size: 10.5px; font-weight: 700;"
        )

    def _on_log(self, message: str) -> None:
        self.statusBar().showMessage(message, 6000)

    def _on_failed(self, message: str) -> None:
        self.statusBar().showMessage(f"抓包失败：{message}", 12000)
        QMessageBox.critical(
            self,
            "抓包失败",
            f"{message}\n\nWindows 在线抓包需要安装 Npcap（勾选 WinPcap API 兼容模式）；"
            "Linux 需要 libpcap 或相应 capability。\n离线分析与内置演示不受影响，可直接使用。",
        )

    def _on_finished(self, report: Any) -> None:
        # The last progress snapshot can pre-date the closing rule pass, so the
        # counters are reconciled from the authoritative report.
        final = dict(self._last_snapshot)
        final.update(
            {
                "packets": report.stats.get("packets", 0),
                "bytes": report.stats.get("wire_bytes", 0),
                "flows": len(report.flows),
                "alerts": len(report.alerts),
                "artifacts": len(report.artifacts),
                "events": len(report.events),
                "event_kinds": dict(
                    Counter(str(row.get("kind") or "other") for row in report.events).most_common(4)
                ),
                "artifact_kinds": dict(
                    Counter(
                        str(row.get("kind") or "").split("/", 1)[0] for row in report.artifacts
                    ).most_common(4)
                ),
                "alerts_high": sum(1 for row in report.alerts if int(row.get("severity", 0)) >= 3),
                "open_flows": sum(1 for row in report.flows if row.get("state") != "closed"),
                "series": [row.get("packets", 0) for _, row in report.series],
                "protocols": dict(report.protocols),
                "apps": dict(report.apps),
                "talkers": [(row["host"], row["bytes"]) for row in report.top_talkers],
            }
        )
        self.dashboard.update_stats(final)
        self.flows_page.refresh(self._report_flow_rows(report))
        self.pps_pill.setText(f"{float(final.get('pps', 0) or 0):,.0f} 包/秒")
        self.flows_pill.setText(f"{len(report.flows):,} 会话")
        self.findings_pill.setText(f"{len(report.alerts):,} 发现")
        self.save_button.setEnabled(True)
        self.statusBar().showMessage(
            f"会话结束 · {report.stats.get('packets', 0):,} 个数据包 · "
            f"{len(report.flows):,} 条会话 · {len(report.alerts):,} 条发现",
            15000,
        )
        self.source_label.setText("会话已结束")

    def _on_running_changed(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.sidebar_dot.set_active(running)
        self.sidebar_badge.setText("抓包中" if running else "空闲")
        if running:
            self.save_button.setEnabled(False)
            self._started_at = time.time()

    # ------------------------------------------------------------------ clock
    def _tick(self) -> None:
        if not self.controller.running:
            return
        elapsed = time.time() - self._started_at
        self.elapsed_label.setText(
            human_duration(elapsed) if elapsed >= 60 else f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}"
        )

    # ------------------------------------------------------------------ housekeeping
    def _clear_views(self) -> None:
        self.dashboard.reset()
        self.flows_page.clear()
        self.packets_page.clear()
        self.media_page.clear()
        self.alerts_page.clear()
        self.elapsed_label.setText("00:00")
        self.save_button.setEnabled(False)

    @staticmethod
    def _report_flow_rows(report: Any) -> list[dict[str, Any]]:
        """Report flows in the shape the table wants (client/server split out)."""
        rows = []
        for row in report.flows:
            enriched = dict(row)
            enriched["client"] = endpoint(str(row.get("src") or ""), int(row.get("sport") or 0))
            enriched["server"] = endpoint(str(row.get("dst") or ""), int(row.get("dport") or 0))
            rows.append(enriched)
        return rows

    def _rule_rows(self) -> list[dict[str, Any]]:
        from ..rules.engine import RuleEngine

        engine = RuleEngine.load_builtin()
        return engine.as_rows()

    def closeEvent(self, event: object) -> None:  # noqa: N802
        if self.controller.running:
            self.controller.stop()
            self.controller.wait(3000)
        super().closeEvent(event)  # type: ignore[arg-type]

    # ------------------------------------------------------------------ programmatic use
    def open_report(self, report: Any) -> None:
        """Populate the UI from a finished report (imports and screenshots)."""
        snapshot = {
            "packets": report.stats.get("packets", 0),
            "bytes": report.stats.get("wire_bytes", 0),
            "flows": len(report.flows),
            "events": len(report.events),
            "alerts": len(report.alerts),
            "artifacts": len(report.artifacts),
            "alerts_high": sum(1 for row in report.alerts if int(row.get("severity", 0)) >= 3),
            "event_kinds": dict(
                Counter(str(row.get("kind") or "other") for row in report.events).most_common(4)
            ),
            "artifact_kinds": dict(
                Counter(str(row.get("kind") or "").split("/", 1)[0] for row in report.artifacts).most_common(
                    4
                )
            ),
            "open_flows": sum(1 for row in report.flows if row.get("state") != "closed"),
            "pps": 0,
            "bps": 0,
            "series": [row.get("packets", 0) for _, row in report.series],
            "protocols": dict(report.protocols),
            "apps": report.apps,
            "talkers": report.top_talkers
            and [(row["host"], row["bytes"]) for row in report.top_talkers]
            or [],
            "streams": len(report.flows),
            "filtered": 0,
            "malformed": report.stats.get("malformed", 0),
            "dropped": report.stats.get("dropped", 0),
        }
        self.dashboard.update_stats(snapshot)
        self.flows_page.refresh(self._report_flow_rows(report))
        self.alerts_page.add_alerts(
            [
                {
                    "ts": alert["ts"],
                    "time": time.strftime("%H:%M:%S", time.localtime(alert["ts"] or time.time())),
                    "title": alert["title"],
                    "rule": alert["rule"],
                    "severity": alert["severity"],
                    "description": alert.get("description", ""),
                    "flow": alert.get("flow", ""),
                    "evidence": alert.get("evidence", {}),
                }
                for alert in report.alerts
            ]
        )
        self.save_button.setEnabled(True)

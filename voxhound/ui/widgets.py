"""Reusable widgets: cards, KPI tiles, charts, hex view, chips.

Everything here paints with QPainter instead of pulling in a charting package.
That keeps the install to Qt itself, makes the visuals match the stylesheet
exactly, and avoids the "chart library default theme" look entirely.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPalette, QPen
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QSizePolicy,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QVBoxLayout,
    QWidget,
)

from ..core.util import hexdump
from .theme import Palette, mono_font, paint_area_chart, paint_donut, tint


class Card(QFrame):
    """Panel with a title row and a content layout."""

    def __init__(self, title: str = "", hint: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(16, 14, 16, 14)
        self._layout.setSpacing(8)
        if title:
            header = QHBoxLayout()
            header.setSpacing(8)
            self.title_label = QLabel(title)
            self.title_label.setObjectName("CardTitle")
            header.addWidget(self.title_label)
            header.addStretch(1)
            self.header_extra = header
            self._layout.addLayout(header)
        else:
            self.header_extra = None
        if hint:
            self.hint_label = QLabel(hint)
            self.hint_label.setObjectName("CardHint")
            self.hint_label.setWordWrap(True)
            self._layout.addWidget(self.hint_label)
        self.body = QVBoxLayout()
        self.body.setSpacing(8)
        self._layout.addLayout(self.body, 1)

    def add(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self.body.addWidget(widget, stretch)
        return widget

    def add_layout(self, layout: object, stretch: int = 0) -> None:
        self.body.addLayout(layout, stretch)  # type: ignore[arg-type]


class ElidedLabel(QLabel):
    """Single-line label that elides instead of clipping; the full text stays in the tooltip."""

    def __init__(
        self,
        text: str = "",
        parent: QWidget | None = None,
        mode: Qt.TextElideMode = Qt.TextElideMode.ElideRight,
    ) -> None:
        super().__init__(parent)
        self._full = text
        self._mode = mode
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setText(text)

    def setText(self, text: str) -> None:  # noqa: N802 - Qt naming
        self._full = text
        self.setToolTip(text)
        self._apply()

    def full_text(self) -> str:
        return self._full

    def resizeEvent(self, event: object) -> None:  # noqa: N802
        super().resizeEvent(event)  # type: ignore[arg-type]
        self._apply()

    def _apply(self) -> None:
        metrics = QFontMetrics(self.font())
        QLabel.setText(self, metrics.elidedText(self._full, self._mode, max(8, self.width())))


class Sparkline(QWidget):
    def __init__(self, palette: Palette, *, accent: str | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self._accent = accent
        self._values: deque[float] = deque(maxlen=60)
        self.setStyleSheet("background: transparent;")
        self.setMinimumHeight(28)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def push(self, value: float) -> None:
        self._values.append(float(value))
        self.update()

    def set_values(self, values: Sequence[float]) -> None:
        self._values = deque(values[-60:], maxlen=60)
        self.update()

    def paintEvent(self, event: object) -> None:  # noqa: N802 - Qt naming
        del event
        painter = QPainter(self)
        rect = QRectF(self.rect()).adjusted(2, 2, -2, -2)
        if len(self._values) >= 2:
            paint_area_chart(
                painter, rect, list(self._values), self._palette, accent=self._accent, baseline=False
            )
        painter.end()


class StatTile(QFrame):
    """KPI tile: label, big value, sub-line, optional sparkline."""

    def __init__(
        self,
        label: str,
        palette: Palette,
        *,
        accent: str | None = None,
        spark: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self._palette = palette
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(2)
        self.label = QLabel(label.upper())
        self.label.setObjectName("StatLabel")
        self.value = QLabel("0")
        self.value.setObjectName("StatValue")
        self.sub = QLabel("")
        self.sub.setObjectName("StatSub")
        layout.addWidget(self.label)
        layout.addWidget(self.value)
        layout.addWidget(self.sub)
        self.spark = Sparkline(palette, accent=accent) if spark else None
        if self.spark is not None:
            layout.addWidget(self.spark)
        if accent:
            self.value.setStyleSheet(f"color: {accent};")

    def set(self, value: str, sub: str = "") -> None:
        self.value.setText(value)
        if sub:
            self.sub.setText(sub)

    def push(self, value: float) -> None:
        if self.spark is not None:
            self.spark.push(value)


class TrafficChart(QWidget):
    """Area chart with a grid, peak marker and current-value annotation."""

    def __init__(self, palette: Palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self._values: deque[float] = deque(maxlen=180)
        self._label = "包/秒"
        self.setStyleSheet("background: transparent;")
        self.setMinimumHeight(150)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_values(self, values: Sequence[float]) -> None:
        self._values = deque(values[-180:], maxlen=180)
        self.update()

    def push(self, value: float) -> None:
        self._values.append(float(value))
        self.update()

    def paintEvent(self, event: object) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        rect = QRectF(self.rect())
        palette = self._palette
        plot = rect.adjusted(0, 24, 0, -18)
        grid_pen = QPen(QColor(palette.border), 1, Qt.PenStyle.DotLine)
        for i in range(1, 4):
            y = plot.top() + plot.height() * i / 4
            painter.setPen(grid_pen)
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
        values = list(self._values)
        if len(values) < 2:
            painter.setPen(QColor(palette.text_faint))
            painter.setFont(QFont(self.font().family(), 9))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "等待流量…")
            painter.end()
            return
        paint_area_chart(painter, plot, values, palette)

        peak = max(values) or 1.0
        current = values[-1]
        # A small marker on the live edge reads as "this is happening now".
        x = plot.right() - 2
        y = plot.bottom() - (current / peak) * (plot.height() - 6) - 1
        halo = QColor(palette.accent)
        halo.setAlpha(60)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(halo)
        painter.drawEllipse(QPointF(x, y), 5.0, 5.0)
        painter.setBrush(QColor(palette.accent))
        painter.drawEllipse(QPointF(x, y), 2.4, 2.4)
        painter.setFont(QFont(self.font().family(), 9))
        painter.setPen(QColor(palette.text_dim))
        painter.drawText(
            QRectF(rect.left(), rect.top(), rect.width(), 16),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            f"{self._label}  ·  当前 {current:.0f}  ·  峰值 {peak:.0f}",
        )
        painter.setPen(QColor(palette.text_faint))
        painter.drawText(
            QRectF(rect.left(), rect.bottom() - 14, rect.width(), 14),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            "最近 3 分钟",
        )
        painter.end()


class DonutChart(QWidget):
    """Donut plus a legend column; slices are (label, value, colour)."""

    def __init__(self, palette: Palette, parent: QWidget | None = None, *, unit: str = "条流") -> None:
        super().__init__(parent)
        self._palette = palette
        self._unit = unit
        self._slices: list[tuple[str, float, str]] = []
        self.setStyleSheet("background: transparent;")
        self.setMinimumHeight(170)

    def set_slices(self, slices: list[tuple[str, float, str]]) -> None:
        self._slices = slices
        self.update()

    def paintEvent(self, event: object) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        palette = self._palette
        rect = QRectF(self.rect())
        size = min(rect.height() - 8, rect.width() * 0.46)
        chart_rect = QRectF(rect.left() + 4, rect.center().y() - size / 2, size, size)
        total = sum(value for _, value, _ in self._slices)
        if total <= 0:
            painter.setPen(QColor(palette.text_faint))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "暂无会话")
            painter.end()
            return
        paint_donut(
            painter,
            chart_rect,
            [(value, color) for _, value, color in self._slices],
            palette,
            thickness=max(10.0, size * 0.11),
        )
        painter.setPen(QColor(palette.text))
        value_font = QFont(self.font().family(), 15)
        value_font.setBold(True)
        painter.setFont(value_font)
        painter.drawText(chart_rect, Qt.AlignmentFlag.AlignCenter, f"{total:,.0f}")
        painter.setFont(QFont(self.font().family(), 8))
        painter.setPen(QColor(palette.text_faint))
        painter.drawText(chart_rect.adjusted(0, 26, 0, 0), Qt.AlignmentFlag.AlignCenter, self._unit)

        legend_x = chart_rect.right() + 18
        y = rect.top() + 6
        metrics = QFontMetrics(QFont(self.font().family(), 9))
        for label, value, color in self._slices[:7]:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(color))
            painter.drawRoundedRect(QRectF(legend_x, y + 3, 8, 8), 2, 2)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QColor(palette.text_dim))
            share = value / total * 100
            text = f"{label}"
            elided = metrics.elidedText(
                text, Qt.TextElideMode.ElideRight, max(40, int(rect.right() - legend_x - 62))
            )
            painter.drawText(QPointF(legend_x + 14, y + 10), elided)
            painter.setPen(QColor(palette.text_faint))
            painter.drawText(
                QRectF(rect.right() - 56, y, 56, 16),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                f"{share:.0f}%",
            )
            y += 21
            if y > rect.bottom() - 14:
                break
        painter.end()


class BarList(QWidget):
    """Horizontal bar list for top talkers / app mix."""

    def __init__(self, palette: Palette, *, accent: str | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self._accent = accent or palette.accent
        self._rows: list[tuple[str, float, str]] = []
        self.setStyleSheet("background: transparent;")
        self.setMinimumHeight(120)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_rows(self, rows: list[tuple[str, float, str]]) -> None:
        self._rows = rows
        self.update()

    def paintEvent(self, event: object) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        palette = self._palette
        metrics = QFontMetrics(self.font())
        if not self._rows:
            painter.setPen(QColor(palette.text_faint))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "暂无数据")
            painter.end()
            return
        peak = max(value for _, value, _ in self._rows) or 1
        row_h = min(26.0, max(18.0, (self.height() - 4) / max(1, len(self._rows))))
        y = 2.0
        for label, value, suffix in self._rows:
            painter.setPen(QColor(palette.text_dim))
            text_width = int(self.width() * 0.42)
            painter.drawText(
                QRectF(0, y, text_width, row_h),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                metrics.elidedText(label, Qt.TextElideMode.ElideMiddle, text_width - 8),
            )
            bar_x = text_width + 6
            bar_w = max(20.0, self.width() - bar_x - 74)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(palette.elevated))
            painter.drawRoundedRect(QRectF(bar_x, y + row_h / 2 - 3.2, bar_w, 6.4), 3.2, 3.2)
            painter.setBrush(QColor(self._accent))
            painter.drawRoundedRect(QRectF(bar_x, y + row_h / 2 - 3.2, bar_w * (value / peak), 6.4), 3.2, 3.2)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QColor(palette.text_faint))
            painter.drawText(
                QRectF(self.width() - 68, y, 68, row_h),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                suffix,
            )
            y += row_h
        painter.end()


class SeverityChip(QLabel):
    def __init__(self, severity: int, palette: Palette, parent: QWidget | None = None) -> None:
        from .theme import severity_color, severity_label

        super().__init__(severity_label(severity), parent)
        color = severity_color(palette, severity).name()
        self.setStyleSheet(
            f"background: {tint(color, 0.14)}; color: {color}; border: 1px solid {tint(color, 0.34)};"
            "border-radius: 8px; padding: 1px 7px; font-size: 10px; font-weight: 700;"
        )
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumWidth(34)


class RatePill(QLabel):
    """Small live indicator for the top bar."""

    def __init__(self, text: str, color: str, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self._color = color
        self.setStyleSheet(
            f"background: {tint(color, 0.13)}; color: {color}; border: 1px solid {tint(color, 0.30)};"
            "border-radius: 9px; padding: 2px 9px; font-size: 10.5px; font-weight: 700; letter-spacing: .4px;"
        )


class HexView(QPlainTextEdit):
    """Read-only hexdump with a monospace font and no soft wrapping."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setObjectName("Mono")
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setStyleSheet(
            "background: #0B1220; border: 1px solid #1E2A3F; border-radius: 8px; padding: 8px;"
        )
        font = QFont("Consolas")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSizeF(10.0)
        self.setFont(font)

    def show_bytes(self, data: bytes, *, limit: int = 8192) -> None:
        self.setPlainText(hexdump(data, limit=limit))


class MonoDelegate(QStyledItemDelegate):
    """Render selected columns in the monospace face without touching the model."""

    def __init__(
        self,
        columns: tuple[int, ...] = (),
        *,
        color: str | None = None,
        size: float = 10.5,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._columns = set(columns)
        self._color = color
        self._size = size

    def initStyleOption(self, option: QStyleOptionViewItem, index: object) -> None:  # noqa: N802
        super().initStyleOption(option, index)  # type: ignore[arg-type]
        if index.column() in self._columns:  # type: ignore[attr-defined]
            option.font = mono_font(self._size)
            if self._color:
                option.palette.setColor(QPalette.ColorRole.Text, QColor(self._color))


_SEVERITY_BY_LABEL = {"信息": 0, "较低": 1, "中": 2, "高": 3, "严重": 4}


def severity_of(row: object) -> int:
    """Severity from a row dict — works for int values and for rule-table labels."""
    if not isinstance(row, dict):
        return 0
    raw = row.get("severity_value", row.get("severity", 0))
    if isinstance(raw, str):
        return _SEVERITY_BY_LABEL.get(raw.strip(), 0)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


class SeverityDelegate(QStyledItemDelegate):
    """Draw the severity as a tinted pill, consistent with the dashboard chips."""

    def __init__(self, palette: Palette, column: int = 1, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self._column = column

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: object) -> None:
        from .theme import severity_color

        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)  # type: ignore[arg-type]
        if index.column() != self._column:  # type: ignore[attr-defined]
            super().paint(painter, opt, index)  # type: ignore[arg-type]
            return

        text = opt.text
        opt.text = ""
        super().paint(painter, opt, index)  # type: ignore[arg-type]  (selection background only)

        severity = severity_of(index.data(Qt.ItemDataRole.UserRole))  # type: ignore[attr-defined]
        color = severity_color(self._palette, severity).name()
        font = QFont(opt.font)
        font.setBold(True)
        font.setPointSizeF(9.0)
        metrics = QFontMetrics(font)
        width = min(max(34.0, metrics.horizontalAdvance(text) + 20.0), opt.rect.width() - 12.0)
        pill = QRectF(opt.rect.left() + 7, opt.rect.center().y() - 9, width, 18)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(QPen(QColor(tint(color, 0.34)), 1))
        painter.setBrush(QColor(tint(color, 0.16)))
        painter.drawRoundedRect(pill, 9, 9)
        painter.setFont(font)
        painter.setPen(QColor(color))
        painter.drawText(pill, Qt.AlignmentFlag.AlignCenter, text)
        painter.restore()

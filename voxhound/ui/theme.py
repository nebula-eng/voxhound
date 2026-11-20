"""Visual language: tokens, QSS and small painting helpers.

The palette is a dark "operations console" scheme: near-black surfaces, one
saturated accent for actions, semantic colours reserved for severity. The QSS is
generated from the tokens so a light theme is a token swap, not a second
stylesheet to maintain by hand.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen


@dataclass(frozen=True, slots=True)
class Palette:
    name: str
    bg: str
    panel: str
    elevated: str
    border: str
    border_strong: str
    text: str
    text_dim: str
    text_faint: str
    accent: str
    accent_hover: str
    accent_soft: str
    good: str
    warn: str
    danger: str
    critical: str
    info: str

    def color(self, key: str) -> QColor:
        return QColor(getattr(self, key))


DARK = Palette(
    name="dark",
    bg="#0A0E15",
    panel="#111726",
    elevated="#162032",
    border="#1E2A3F",
    border_strong="#2A3A55",
    text="#E8EEF9",
    text_dim="#93A2B8",
    text_faint="#5E6E86",
    accent="#4C8DFF",
    accent_hover="#6BA1FF",
    accent_soft="#16294A",
    good="#2FD3A5",
    warn="#F5A524",
    danger="#FF6B6B",
    critical="#FF3B5C",
    info="#5AC8FA",
)

SEVERITY_KEYS = ("info", "info", "warn", "danger", "critical")


def blend(foreground: str, background: str, alpha: float) -> str:
    """Opaque mix of two tokens — for surfaces that must cover the style's own paint."""
    front = QColor(foreground)
    back = QColor(background)
    ratio = max(0.0, min(1.0, alpha))
    red = int(front.red() * ratio + back.red() * (1 - ratio))
    green = int(front.green() * ratio + back.green() * (1 - ratio))
    blue = int(front.blue() * ratio + back.blue() * (1 - ratio))
    return f"#{red:02X}{green:02X}{blue:02X}"


def tint(color: str | QColor, alpha: float) -> str:
    """QSS ``rgba()`` from a palette token.

    Qt parses an eight-digit literal as ``#AARRGGBB``, so appending an alpha
    suffix to ``#4C8DFF`` yields a moss-green surprise instead of a translucent
    blue. Always build translucent colours through this helper.
    """
    value = QColor(color)
    return (
        f"rgba({value.red()}, {value.green()}, {value.blue()}, {int(round(max(0.0, min(1.0, alpha)) * 255))})"
    )


def severity_color(palette: Palette, severity: int) -> QColor:
    key = SEVERITY_KEYS[min(4, max(0, int(severity)))]
    return palette.color(key)


def severity_label(severity: int) -> str:
    return ("信息", "较低", "中", "高", "严重")[min(4, max(0, int(severity)))]


def qss(palette: Palette) -> str:
    """One stylesheet for the whole app, keyed off object names and classes."""
    p = palette
    return f"""
QWidget {{
    color: {p.text};
    font-family: "Inter", "Segoe UI Variable", "Segoe UI", "PingFang SC", "Microsoft YaHei UI", sans-serif;
    font-size: 12.5px;
}}
QMainWindow, QDialog, QStackedWidget, QWidget#Page {{ background: {p.bg}; }}
QLabel, QCheckBox, QRadioButton {{ background: transparent; }}
QWidget#Card QLabel {{ background: transparent; }}

#Sidebar {{ background: {p.panel}; border-right: 1px solid {p.border}; }}
#SidebarBrand {{ font-size: 15px; font-weight: 800; letter-spacing: 2px; color: {p.text}; }}
#SidebarVersion {{ color: {p.text_faint}; font-size: 10.5px; letter-spacing: .6px; }}
#SidebarHint {{ color: {p.text_dim}; font-size: 10.5px; }}
#NavButton {{
    text-align: left; padding: 9px 14px; border: none; border-radius: 8px;
    color: {p.text_dim}; font-size: 12.5px; font-weight: 600; letter-spacing: .4px;
    background: transparent;
}}
#NavButton:hover {{ background: {p.elevated}; color: {p.text}; }}
#NavButton:checked {{
    background: {p.accent_soft}; color: {p.text};
    border-left: 2px solid {p.accent}; padding-left: 12px;
}}
#NavBadge {{
    background: {p.critical}; color: #fff; border-radius: 8px; padding: 0 6px;
    font-size: 10px; font-weight: 700;
}}
#TopBar {{ background: {p.panel}; border-bottom: 1px solid {p.border}; }}
#PageTitle {{ font-size: 17px; font-weight: 700; letter-spacing: .2px; }}
#PageSubtitle {{ color: {p.text_dim}; font-size: 11.5px; }}

#Card {{ background: {p.panel}; border: 1px solid {p.border}; border-radius: 12px; }}
#CardTitle {{ font-size: 12px; font-weight: 700; color: {p.text}; letter-spacing: .3px; }}
#CardHint {{ color: {p.text_faint}; font-size: 11px; }}
#StatValue {{ font-size: 21px; font-weight: 700; }}
#StatLabel {{ color: {p.text_dim}; font-size: 10.5px; letter-spacing: 1.1px; font-weight: 600; }}
#StatSub {{ color: {p.text_faint}; font-size: 10.5px; }}
#Mono {{ font-family: "JetBrains Mono", "Cascadia Mono", "Consolas", monospace; font-size: 11.5px; }}
#Dim {{ color: {p.text_dim}; }}
#Faint {{ color: {p.text_faint}; }}

QPushButton {{
    background: {p.elevated}; color: {p.text}; border: 1px solid {p.border_strong};
    border-radius: 8px; padding: 7px 14px; font-weight: 600;
}}
QPushButton:hover {{ border-color: {p.accent}; }}
QPushButton:pressed {{ background: {p.border}; }}
QPushButton#Primary {{ background: {p.accent}; border-color: {p.accent}; color: #06101F; }}
QPushButton#Primary:hover {{ background: {p.accent_hover}; border-color: {p.accent_hover}; }}
QPushButton#Danger {{ background: transparent; border-color: {p.danger}; color: {p.danger}; }}
QPushButton#Ghost {{ background: transparent; border-color: {p.border_strong}; }}
QPushButton:disabled {{ color: {p.text_faint}; border-color: {p.border}; background: transparent; }}

QLineEdit, QComboBox, QSpinBox {{
    background: {p.elevated}; border: 1px solid {p.border}; border-radius: 7px;
    padding: 6px 9px; selection-background-color: {p.accent}; color: {p.text};
}}
QLineEdit:focus, QComboBox:focus {{ border-color: {p.accent}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QSpinBox::up-button, QSpinBox::down-button {{ width: 0; height: 0; border: none; }}
QComboBox QAbstractItemView {{
    background: {p.elevated}; border: 1px solid {p.border_strong};
    selection-background-color: {p.accent_soft}; outline: none;
}}

QTableView {{
    background: {p.panel}; alternate-background-color: {p.elevated};
    border: none; gridline-color: transparent;
    selection-background-color: {blend(p.accent, p.panel, 0.22)};
    selection-color: {p.text}; outline: none;
}}
QTableView::item {{ padding: 4px 8px; border: none; }}
QTableView::item:selected {{ background: {blend(p.accent, p.panel, 0.22)}; color: {p.text}; }}
QTableView::item:selected:!active {{ background: {blend(p.accent, p.panel, 0.16)}; color: {p.text}; }}
QHeaderView::section {{
    background: {p.panel}; color: {p.text_faint}; border: none;
    border-bottom: 1px solid {p.border}; padding: 7px 8px;
    font-size: 10.5px; font-weight: 700; letter-spacing: .8px;
}}
QTableCornerButton::section {{ background: {p.panel}; border: none; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {p.border_strong}; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {p.text_faint}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; }}
QScrollBar::handle:horizontal {{ background: {p.border_strong}; border-radius: 5px; min-width: 30px; }}

QSplitter::handle {{ background: {p.border}; }}
QSplitter::handle:horizontal {{ width: 1px; }}
QSplitter::handle:vertical {{ height: 1px; }}

QTabWidget::pane {{ border: 1px solid {p.border}; border-radius: 10px; top: -1px; }}
QTabBar::tab {{
    background: transparent; color: {p.text_dim}; padding: 7px 14px; margin-right: 4px;
    border-radius: 7px; font-weight: 600;
}}
QTabBar::tab:selected {{ background: {p.elevated}; color: {p.text}; }}

QStatusBar {{ background: {p.panel}; border-top: 1px solid {p.border}; color: {p.text_dim}; }}
QStatusBar::item {{ border: none; }}

QToolTip {{
    background: {p.elevated}; color: {p.text}; border: 1px solid {p.border_strong};
    padding: 5px 7px; border-radius: 6px;
}}

QCheckBox {{ spacing: 8px; color: {p.text_dim}; }}
QCheckBox::indicator {{
    width: 15px; height: 15px; border-radius: 4px;
    border: 1px solid {p.border_strong}; background: {p.elevated};
}}
QCheckBox::indicator:checked {{ background: {p.accent}; border-color: {p.accent}; }}
"""


def paint_area_chart(
    painter: QPainter,
    rect: QRectF,
    values: list[float],
    palette: Palette,
    *,
    accent: str | None = None,
    baseline: bool = True,
) -> None:
    """Filled area chart with a soft gradient — used by the dashboard and tiles."""
    if len(values) < 2:
        return
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    peak = max(values) or 1.0
    step = rect.width() / (len(values) - 1)
    points = [
        (rect.left() + i * step, rect.bottom() - (v / peak) * (rect.height() - 6) - 1)
        for i, v in enumerate(values)
    ]
    path = QPainterPath()
    path.moveTo(points[0][0], points[0][1])
    for x, y in points[1:]:
        path.lineTo(x, y)
    area = QPainterPath(path)
    area.lineTo(rect.right(), rect.bottom())
    area.lineTo(rect.left(), rect.bottom())
    area.closeSubpath()

    gradient = QLinearGradient(rect.topLeft(), rect.bottomLeft())
    base = QColor(accent or palette.accent)
    top = QColor(base)
    top.setAlpha(110)
    bottom = QColor(base)
    bottom.setAlpha(6)
    gradient.setColorAt(0.0, top)
    gradient.setColorAt(1.0, bottom)
    painter.fillPath(area, gradient)
    pen = QPen(base, 1.6)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.drawPath(path)
    if baseline:
        painter.setPen(QPen(QColor(palette.border), 1))
        painter.drawLine(rect.bottomLeft(), rect.bottomRight())
    painter.restore()


def paint_donut(
    painter: QPainter,
    rect: QRectF,
    slices: list[tuple[float, str]],
    palette: Palette,
    *,
    thickness: float = 14.0,
) -> None:
    total = sum(v for v, _ in slices) or 1.0
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    box = rect.adjusted(thickness / 2, thickness / 2, -thickness / 2, -thickness / 2)
    start = 90 * 16
    for value, color in slices:
        span = -int(360 * 16 * (value / total))
        pen = QPen(QColor(color), thickness)
        pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        painter.setPen(pen)
        painter.drawArc(box, start, span)
        start += span
    painter.restore()


def mono_font(size: float = 11.5) -> QFont:
    font = QFont("JetBrains Mono")
    if not QFont(font).exactMatch():
        font = QFont("Cascadia Mono")
        if not font.exactMatch():
            font = QFont("Consolas")
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setPointSizeF(size)
    return font

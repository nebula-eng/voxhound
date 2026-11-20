"""Application bootstrap.

Two entry points:

``main()``   — the ``voxhound-gui`` console script.
``launch()`` — used by ``voxhound gui`` and by the screenshot tooling, returns the
                Qt exit code and accepts an optional capture target.

Qt is imported here and nowhere else in the engine, which is what keeps
``pip install voxhound`` dependency-free.
"""

from __future__ import annotations

import sys

from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication

from .. import __version__
from .main_window import MainWindow
from .theme import DARK, blend


def build_application(argv: list[str] | None = None) -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication(argv or sys.argv)
    app.setApplicationName("VoxHound")
    app.setApplicationDisplayName(f"VoxHound {__version__}")
    app.setOrganizationName("VoxHound")
    app.setStyle("Fusion")
    font = QFont("Segoe UI Variable")
    if not font.exactMatch():
        font = QFont("Segoe UI")
    font.setPointSizeF(9.5)
    app.setFont(font)
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(DARK.bg))
    palette.setColor(QPalette.ColorRole.Base, QColor(DARK.panel))
    palette.setColor(QPalette.ColorRole.Text, QColor(DARK.text))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(DARK.text))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(blend(DARK.accent, DARK.panel, 0.22)))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(DARK.text))
    app.setPalette(palette)
    return app


def launch(*, spec: str | None = None, filter_expr: str = "", autostart: bool = False) -> int:
    app = build_application()
    window = MainWindow(DARK, spec=spec, filter_expr=filter_expr)
    window.show()
    if autostart and spec:
        window.start_capture()
    return int(app.exec())


def main() -> int:
    return launch(spec=sys.argv[1] if len(sys.argv) > 1 else None)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

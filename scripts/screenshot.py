#!/usr/bin/env python3
"""Render the UI screenshots used by the README.

Drives a *real* demo session through the actual application — no mocked models —
so a broken pipeline shows up as an empty screenshot instead of a pretty lie.

    python scripts/screenshot.py [output-dir]
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
if sys.platform.startswith("win"):
    # The Windows platform plugin is what renders the fonts the README shows;
    # on Linux/macOS leave Qt's default alone or the plugin lookup fails.
    os.environ.setdefault("QT_QPA_PLATFORM", "windows")

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402

from voxhound.ui.app import build_application  # noqa: E402
from voxhound.ui.main_window import MainWindow  # noqa: E402

PAGES = ("dashboard", "flows", "packets", "media", "alerts", "settings")


def pump(ms: int) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def main(argv: list[str]) -> int:
    target = Path(argv[1] if len(argv) > 1 else "docs/screenshots")
    target.mkdir(parents=True, exist_ok=True)
    build_application([])
    window = MainWindow()
    window.resize(1600, 1000)
    window.show()
    pump(400)

    window.start_capture()
    deadline = time.time() + 120
    while time.time() < deadline:
        pump(200)
        if not window.controller.running:
            break
    pump(800)

    for page in PAGES:
        window._set_page(page)
        pump(350)
        path = target / f"{page}.png"
        window.grab().save(str(path))
        sys.stdout.write(f"wrote {path}\n")

    report = window.controller.report
    if report is None:
        sys.stderr.write("截图完成，但本次会话没有生成报告\n")
        return 1
    from voxhound.export.report import write_html

    html_path = write_html(report, target.parent / "sample-report.html")
    sys.stdout.write(f"wrote {html_path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

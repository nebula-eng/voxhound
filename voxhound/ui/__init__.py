"""Desktop front-end (PySide6). Imported lazily so the engine stays Qt-free."""

from __future__ import annotations

__all__ = ["launch"]


def launch(**kwargs: object) -> int:
    from .app import launch as _launch

    return int(_launch(**kwargs))  # type: ignore[arg-type]

"""VoxHound — passive network forensics workbench for voice and media traffic.

The package is deliberately split into two halves:

``voxhound.capture`` / ``decode`` / ``app`` / ``flows`` / ``media`` / ``rules``
    Pure standard-library engine. No third-party imports, importable on a bare
    interpreter, exercisable from CI and from the CLI.

``voxhound.ui``
    Optional PySide6 desktop front-end. Imported lazily so the engine keeps
    working on machines without Qt.

Typical programmatic use::

    from voxhound.capture.source import open_source
    from voxhound.engine import Engine

    engine = Engine()
    report = engine.run(open_source("capture.pcapng"))
    print(report.summary())
"""

from __future__ import annotations

from .version import __version__, __version_tuple__

__all__ = ["__version__", "__version_tuple__"]

"""Single source of truth for the project version.

``voxhound.version.__version__`` is what the CLI, the GUI and the generated
reports stamp into their output. ``pyproject.toml`` carries the same value for
packaging; ``tests/test_version.py`` keeps the two in sync.
"""

from __future__ import annotations

__version__ = "1.0.0"
__version_tuple__: tuple[int, int, int] = (1, 0, 0)

#: Human readable product string used in window titles and report headers.
APP_NAME = "VoxHound"
APP_TAGLINE = "Passive network forensics for voice and media traffic"
APP_HOME = "https://github.com/nebula-eng/voxhound"

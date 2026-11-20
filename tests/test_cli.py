"""CLI entry-point tests.

The Windows GUI scripts run under ``pythonw``, where ``sys.stdout`` is ``None``.
An import-time ``sys.stdout.isatty()`` call used to crash the app before the
window opened; this module keeps that from regressing.
"""

from __future__ import annotations

import subprocess
import sys


def test_cli_import_survives_missing_stdout() -> None:
    code = "import sys; sys.stdout = None; sys.stderr = None; import voxhound.cli"
    result = subprocess.run(  # noqa: PLW1510 - returncode is asserted explicitly
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_version_subcommand_prints_platform() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "voxhound", "version"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0
    assert "VoxHound" in result.stdout
    assert "Python" in result.stdout


def test_live_filter_is_left_to_the_kernel() -> None:
    """Valid BPF outside the engine's subset must not be re-compiled for sniff."""
    from argparse import Namespace

    from voxhound.cli import _build_engine

    bpf = "tcp[tcpflags] & tcp-syn != 0"
    args = Namespace(
        command="sniff",
        filter=bpf,
        verify_checksums=False,
        no_rules=True,
        no_heuristics=True,
        rules=None,
    )
    engine = _build_engine(args)
    # The engine's predicate must be the accept-all placeholder, not a parse of
    # the BPF string (which would have raised above).
    assert engine.filter(object()) is True
    assert engine.filter_expr == bpf  # still recorded for the report


def test_every_export_format_is_written_together(tmp_path) -> None:
    """``--json`` used to crash before any file was written.

    ``Report.summary()`` touched ``alert.severity`` while the report actually
    carries dicts, so a run that asked for JSON produced **nothing at all** —
    including the HTML report that shared the same invocation.
    """
    import json

    target = tmp_path / "out"
    command = [
        sys.executable,
        "-m",
        "voxhound",
        "demo",
        "--quiet",
        "--report",
        str(target / "report.html"),
        "--json",
        str(target / "report.json"),
        "--markdown",
        str(target / "summary.md"),
        "--csv",
        str(target / "flows.csv"),
        "--ndjson",
        str(target / "events.ndjson"),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    # A demo contains high-severity findings, so 1 is the documented success code.
    assert result.returncode == 1, result.stderr
    assert "Traceback" not in result.stderr

    for name in ("report.html", "report.json", "summary.md", "flows.csv", "events.ndjson"):
        path = target / name
        assert path.exists() and path.stat().st_size > 0, f"{name} missing"

    payload = json.loads((target / "report.json").read_text(encoding="utf-8"))
    assert payload["summary"]["alerts"] == len(payload["alerts"])
    assert payload["summary"]["alerts_high"] <= payload["summary"]["alerts"]
    header = (target / "flows.csv").read_text(encoding="utf-8").splitlines()[0]
    assert "ja3" in header and "ja4t" in header

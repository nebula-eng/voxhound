"""SQLite persistence for sessions, flows, events, alerts and artifacts.

Why SQLite and not JSON dumps: an analyst reviewing a 300k-flow capture needs
filtering and aggregation, and ``sqlite3`` is in the standard library. The schema
is small, indexed for the queries the UI actually issues, and versioned so a
future release can migrate rather than guess.

Artifact *bytes* are not stored in the database — only metadata and hashes. Media
lives on disk, referenced by path, because a multi-gigabyte voice dump has no
business inside a transaction log.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   REAL NOT NULL,
    finished_at  REAL,
    source       TEXT,
    filter       TEXT,
    tool_version TEXT,
    packets      INTEGER DEFAULT 0,
    bytes        INTEGER DEFAULT 0,
    flows        INTEGER DEFAULT 0,
    alerts       INTEGER DEFAULT 0,
    stats        TEXT
);

CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    src         TEXT, sport INTEGER, dst TEXT, dport INTEGER,
    proto       TEXT, app TEXT, sni TEXT, ja3 TEXT, ja4 TEXT, ja4s TEXT, ja4t TEXT,
    os_hint     TEXT, tls_version TEXT, cipher TEXT, cert_cn TEXT,
    packets     INTEGER, bytes INTEGER, duration REAL,
    first_ts    REAL, last_ts REAL, state TEXT, tags TEXT, rtt_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_flows_session ON flows(session_id);
CREATE INDEX IF NOT EXISTS idx_flows_app ON flows(app);
CREATE INDEX IF NOT EXISTS idx_flows_sni ON flows(sni);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts         REAL, kind TEXT, title TEXT, severity INTEGER, flow TEXT, detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts          REAL, rule_id TEXT, title TEXT, severity INTEGER,
    description TEXT, flow TEXT, evidence TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);

CREATE TABLE IF NOT EXISTS artifacts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts         REAL, kind TEXT, name TEXT, size INTEGER, sha256 TEXT,
    source     TEXT, flow TEXT, path TEXT, meta TEXT
);
CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts(session_id);
"""


class SessionStore:
    """Thin, explicit wrapper — no ORM, no magic, no surprise transactions."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._conn: sqlite3.Connection | None = None
        self.session_id: int | None = None

    # ------------------------------------------------------------------ lifecycle
    def open(self) -> SessionStore:
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),)
        )
        self._conn.commit()
        return self

    def _migrate(self) -> None:
        """Bring an existing database up to the current schema.

        ``CREATE TABLE IF NOT EXISTS`` does not add columns to a database that
        was created by an older release, so each additive change is applied
        explicitly. Only additive migrations are allowed here: dropping or
        retyping a column would silently destroy a previous case.
        """
        assert self._conn is not None
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(flows)")}
        if "ja3" not in columns:
            self._conn.execute("ALTER TABLE flows ADD COLUMN ja3 TEXT")
        self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.commit()
            self._conn.close()
            self._conn = None

    def __enter__(self) -> SessionStore:
        return self.open()

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("SessionStore.open() was not called")
        return self._conn

    # ------------------------------------------------------------------ writes
    def start_session(self, *, source: str, filter_expr: str, tool_version: str) -> int:
        cursor = self.conn.execute(
            "INSERT INTO sessions(started_at, source, filter, tool_version) VALUES(?,?,?,?)",
            (time.time(), source, filter_expr, tool_version),
        )
        self.conn.commit()
        self.session_id = int(cursor.lastrowid)
        return self.session_id

    def add_flows(self, rows: Sequence[dict[str, Any]]) -> None:
        if not rows or self.session_id is None:
            return
        self.conn.executemany(
            """INSERT INTO flows(session_id, src, sport, dst, dport, proto, app, sni, ja3, ja4, ja4s,
                                 ja4t, os_hint, tls_version, cipher, cert_cn, packets, bytes, duration,
                                 first_ts, last_ts, state, tags, rtt_ms)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                (
                    self.session_id,
                    r.get("src"),
                    r.get("sport"),
                    r.get("dst"),
                    r.get("dport"),
                    r.get("proto"),
                    r.get("app"),
                    r.get("sni"),
                    r.get("ja3"),
                    r.get("ja4"),
                    r.get("ja4s"),
                    r.get("ja4t"),
                    r.get("os"),
                    r.get("tls_version"),
                    r.get("cipher"),
                    r.get("cert_cn"),
                    r.get("packets"),
                    r.get("bytes"),
                    r.get("duration"),
                    r.get("first_ts"),
                    r.get("last_ts"),
                    r.get("state"),
                    r.get("tags"),
                    r.get("rtt_ms"),
                )
                for r in rows
            ],
        )
        self.conn.commit()

    def add_events(self, rows: Sequence[dict[str, Any]]) -> None:
        if not rows or self.session_id is None:
            return
        self.conn.executemany(
            "INSERT INTO events(session_id, ts, kind, title, severity, flow, detail) VALUES(?,?,?,?,?,?,?)",
            [
                (
                    self.session_id,
                    r.get("ts"),
                    r.get("kind"),
                    r.get("title"),
                    r.get("severity"),
                    r.get("flow"),
                    json.dumps(r.get("detail", {}), ensure_ascii=False, default=str),
                )
                for r in rows
            ],
        )
        self.conn.commit()

    def add_alerts(self, rows: Sequence[dict[str, Any]]) -> None:
        if not rows or self.session_id is None:
            return
        self.conn.executemany(
            """INSERT INTO alerts(session_id, ts, rule_id, title, severity, description, flow, evidence)
               VALUES(?,?,?,?,?,?,?,?)""",
            [
                (
                    self.session_id,
                    r.get("ts"),
                    r.get("rule"),
                    r.get("title"),
                    r.get("severity"),
                    r.get("description"),
                    r.get("flow"),
                    json.dumps(r.get("evidence", {}), ensure_ascii=False, default=str),
                )
                for r in rows
            ],
        )
        self.conn.commit()

    def add_artifacts(self, rows: Sequence[dict[str, Any]], paths: dict[str, str] | None = None) -> None:
        if not rows or self.session_id is None:
            return
        paths = paths or {}
        self.conn.executemany(
            """INSERT INTO artifacts(session_id, ts, kind, name, size, sha256, source, flow, path, meta)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            [
                (
                    self.session_id,
                    r.get("ts"),
                    r.get("kind"),
                    r.get("name"),
                    r.get("size"),
                    r.get("sha256"),
                    r.get("source"),
                    r.get("flow"),
                    paths.get(str(r.get("sha256"))),
                    json.dumps(r.get("meta", {}), ensure_ascii=False, default=str),
                )
                for r in rows
            ],
        )
        self.conn.commit()

    def finish_session(self, stats: dict[str, Any], *, source: str | None = None) -> None:
        if self.session_id is None:
            return
        self.conn.execute(
            """UPDATE sessions SET finished_at=?, packets=?, bytes=?, flows=?, alerts=?, stats=?,
                                   source=COALESCE(?, source)
               WHERE id=?""",
            (
                time.time(),
                stats.get("packets", 0),
                stats.get("bytes", 0),
                stats.get("flows", 0),
                stats.get("alerts", 0),
                json.dumps(stats, ensure_ascii=False, default=str),
                source,
                self.session_id,
            ),
        )
        self.conn.commit()

    # ------------------------------------------------------------------ reads
    def sessions(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.conn.execute("SELECT * FROM sessions ORDER BY id DESC")]

    def flows(
        self, *, session_id: int | None = None, app: str | None = None, limit: int = 1000
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM flows WHERE session_id=?"
        params: list[Any] = [session_id or self.session_id]
        if app:
            query += " AND app=?"
            params.append(app)
        query += " ORDER BY bytes DESC LIMIT ?"
        params.append(limit)
        return [dict(row) for row in self.conn.execute(query, params)]

    def alerts(self, *, session_id: int | None = None, limit: int = 1000) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.conn.execute(
                "SELECT * FROM alerts WHERE session_id=? ORDER BY severity DESC, ts DESC LIMIT ?",
                (session_id or self.session_id, limit),
            )
        ]

    def count(self, table: str, *, session_id: int | None = None) -> int:
        if table not in ("flows", "events", "alerts", "artifacts", "sessions"):
            raise ValueError(f"unknown table {table!r}")
        row = self.conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE session_id=?", (session_id or self.session_id,)
        ).fetchone()
        return int(row[0]) if row else 0


def save_report(report: Any, path: str | Path, *, artifacts_dir: str | None = None) -> int:
    """Persist a finished :class:`~voxhound.engine.Report`; returns the session id."""
    with SessionStore(path) as store:
        session_id = store.start_session(
            source=report.stats.get("capture_filter", "") or "analysis",
            filter_expr=report.stats.get("capture_filter", ""),
            tool_version=report.version,
        )
        store.add_flows(report.flows)
        store.add_events(report.events)
        store.add_alerts(report.alerts)
        store.add_artifacts(report.artifacts)
        store.finish_session({**report.stats, "flows": len(report.flows), "alerts": len(report.alerts)})
        del artifacts_dir
        return session_id


def write_artifacts(artifacts: Iterable[Any], directory: str | Path) -> list[Path]:
    """Write carved payloads to disk under ``directory``; returns written paths."""
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for index, artifact in enumerate(artifacts):
        name = f"{index:03d}-{artifact.name}"
        path = target / name
        path.write_bytes(artifact.data)
        written.append(path)
    return written

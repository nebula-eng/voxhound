"""End-to-end tests: the demo run must produce every feature we claim.

These assertions are deliberately *content* assertions (a real SNI from an
encrypted QUIC handshake, a playable WAV, a rule hit for the beacon pattern)
rather than "the list is not empty". A regression in any layer shows up here.
"""

from __future__ import annotations

import contextlib
import io
import json
import wave

import pytest

from voxhound.engine import Engine
from voxhound.export.io import extract_pcap
from voxhound.export.report import render_html, render_markdown
from voxhound.simulate import write_demo_pcap
from voxhound.store.sqlite import SessionStore, save_report


@pytest.fixture(scope="module")
def report():
    engine = Engine()
    return engine.run_spec("demo")


def test_engine_sees_every_simulated_protocol(report) -> None:
    apps = report.apps
    for expected in ("DNS", "TLS", "HTTP", "HTTP/2", "QUIC", "RTP"):
        assert expected in apps, f"{expected} missing from {apps}"
    assert report.stats["packets"] > 250
    assert len(report.flows) >= 40


def test_tls_fingerprints_and_certificate_identity(report) -> None:
    tls_flow = next(row for row in report.flows if row["app"] == "TLS")
    assert tls_flow["sni"] == "api.example.com"
    assert tls_flow["ja4"].startswith("t13d")
    assert tls_flow["ja4s"].startswith("t13")
    assert tls_flow["ja4t"].count("_") == 3
    assert tls_flow["cert_cn"] == "api.example.com"


def test_quic_initial_is_decrypted_and_sni_recovered(report) -> None:
    quic = [event for event in report.events if event["kind"] == "quic"]
    client_hello = next(event for event in quic if "ClientHello" in event["title"])
    assert "quic.example.com" in client_hello["title"]
    assert client_hello["detail"]["decrypted"] is True
    assert client_hello["detail"]["ja4"].startswith("q13d")


def test_voice_call_is_reconstructed_as_playable_wav(report) -> None:
    wav_artifacts = [a for a in report.artifacts if a["kind"] == "audio/wav"]
    assert len(wav_artifacts) == 2  # one per SSRC
    audio = wav_artifacts[0]
    assert audio["size"] > 30_000
    assert audio["meta"]["codec"] == "PCMU"
    assert audio["meta"]["duration_s"] == pytest.approx(2.0, abs=0.05)


def test_wav_bytes_are_a_valid_container() -> None:
    engine = Engine()
    engine.run_spec("demo")
    wav_artifact = next(a for a in engine.artifacts if a.kind == "audio/wav")
    with wave.open(io.BytesIO(wav_artifact.data), "rb") as handle:
        assert handle.getnchannels() == 1
        assert handle.getframerate() == 8000
        assert handle.getsampwidth() == 2
        assert handle.getnframes() == 16000


def test_behavioural_and_rule_findings_fire(report) -> None:
    rules = {alert["rule"] for alert in report.alerts}
    assert "heuristic-beacon" in rules
    assert "heuristic-port-scan" in rules
    assert "dns-long-label" in rules
    assert "dns-algorithmic-domain" in rules


def test_html_report_is_self_contained_and_complete(report) -> None:
    html = render_html(report)
    assert html.startswith("<!DOCTYPE html>")
    assert 'lang="zh-CN"' in html
    assert "api.example.com" in html
    assert "quic.example.com" in html
    assert "流量时间线" in html and "会话明细" in html
    assert "http://" not in html.split("<body")[1][:2000]  # 正文不得引用远程资源
    assert "<svg" in html
    assert "None" not in html.replace("none", "")
    markdown = render_markdown(report)
    assert "## 发现" in markdown and "## 主要会话" in markdown


def test_sqlite_store_roundtrip(tmp_path, report) -> None:
    db = tmp_path / "session.db"
    session_id = save_report(report, db)
    assert session_id >= 1
    with SessionStore(db) as store:
        store.session_id = session_id
        assert store.count("flows") == len(report.flows)
        assert store.count("alerts") == len(report.alerts)
        top = store.flows(limit=5)
        assert top[0]["bytes"] >= top[-1]["bytes"]
        assert store.sessions()[0]["packets"] == report.stats["packets"]


def test_pcap_extract_filters_frames(tmp_path) -> None:
    source = tmp_path / "demo.pcap"
    count = write_demo_pcap(str(source))
    assert count > 250
    target = tmp_path / "tls-only.pcap"
    result = extract_pcap(source, target, "tcp port 443")
    assert result["written"] > 0
    assert target.stat().st_size > 24
    assert result["written"] < count


def test_engine_filter_reduces_flow_count(tmp_path) -> None:
    source = tmp_path / "demo.pcap"
    write_demo_pcap(str(source))
    unfiltered = Engine().analyze_file(source)
    filtered = Engine(filter_expr="udp").analyze_file(source)
    assert len(filtered.flows) < len(unfiltered.flows)
    assert all(row["proto"] == "UDP" for row in filtered.flows)


def test_report_json_serialises(report) -> None:
    payload = json.dumps({"flows": report.flows, "alerts": report.alerts}, default=str)
    assert len(payload) > 1000


def test_store_migrates_old_database_additively(tmp_path) -> None:
    """An older case database must gain new columns instead of failing."""
    import sqlite3

    from voxhound.store.sqlite import SessionStore

    path = tmp_path / "legacy.db"
    legacy = sqlite3.connect(path)
    legacy.executescript(
        """
        CREATE TABLE flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER, src TEXT, sport INTEGER, dst TEXT, dport INTEGER,
            proto TEXT, app TEXT, sni TEXT, ja4 TEXT, ja4s TEXT, ja4t TEXT,
            os_hint TEXT, tls_version TEXT, cipher TEXT, cert_cn TEXT,
            packets INTEGER, bytes INTEGER, duration REAL,
            first_ts REAL, last_ts REAL, state TEXT, tags TEXT, rtt_ms REAL
        );
        """
    )
    legacy.commit()
    legacy.close()

    with SessionStore(path) as store:
        store.start_session(source="legacy", filter_expr="", tool_version="0.9")
        store.add_flows(
            [
                {
                    "src": "10.0.0.1",
                    "sport": 1234,
                    "dst": "10.0.0.2",
                    "dport": 443,
                    "proto": "TCP",
                    "ja3": "edf2a53c92b9e01c23f342cdfb863ae6",
                    "sni": "example.com",
                }
            ]
        )

    # sqlite3's context manager commits but does not close; closing matters here
    # because an unclosed handle keeps the WAL file alive on Windows.
    with contextlib.closing(sqlite3.connect(path)) as check:
        value = check.execute("SELECT ja3 FROM flows").fetchone()[0]
    assert value == "edf2a53c92b9e01c23f342cdfb863ae6"

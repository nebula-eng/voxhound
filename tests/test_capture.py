"""Capture IO, reassembly and filter tests.

These are the parts where a silent bug produces *plausible but wrong* output —
the worst failure mode for a forensics tool — so they get the most assertions.
"""

from __future__ import annotations

import gzip
import io
import struct

import pytest

from voxhound.capture.filter import FilterSyntaxError, compile_filter
from voxhound.capture.pcapfile import PcapReader, PcapWriter, sniff_format
from voxhound.capture.pcapng import PcapNgReader
from voxhound.core.model import Packet, RawPacket
from voxhound.flows.stream import DirectionReassembler


# --------------------------------------------------------------------------- pcap
def _packets() -> list[RawPacket]:
    return [
        RawPacket(ts=1.5, data=b"\x01" * 60, caplen=60, wirelen=64),
        RawPacket(ts=2.25, data=b"\x02" * 100, caplen=100, wirelen=100),
    ]


def test_pcap_roundtrip_preserves_timestamps_and_lengths() -> None:
    buffer = io.BytesIO()
    writer = PcapWriter(buffer, linktype=1)
    for pkt in _packets():
        writer.write(pkt)
    raw = buffer.getvalue()
    reader = PcapReader(io.BytesIO(raw))
    out = list(reader)
    assert [p.caplen for p in out] == [60, 100]
    assert [p.wirelen for p in out] == [64, 100]
    assert out[0].ts == pytest.approx(1.5, abs=1e-6)
    assert out[1].ts == pytest.approx(2.25, abs=1e-6)


def test_pcap_magic_detection() -> None:
    buffer = io.BytesIO()
    writer = PcapWriter(buffer, linktype=1)
    writer.write(_packets()[0])
    assert sniff_format(buffer.getvalue()[:4]) == "pcap"


def test_pcapng_enhanced_packet_block_is_read() -> None:
    def block(block_type: int, body: bytes) -> bytes:
        total = 12 + len(body)
        return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)

    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = block(0x0A0D0D0A, shb_body)
    idb = block(0x00000001, struct.pack("<HHI", 1, 0, 0) + struct.pack("<HH", 0, 0))
    ts = 3_000_000  # microseconds
    epb_body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, 4, 4) + b"abcd"
    epb = block(0x00000006, epb_body + b"\x00" * 0)
    data = shb + idb + epb

    reader = PcapNgReader(io.BytesIO(data))
    packets = list(reader)
    assert len(packets) == 1
    assert packets[0].data == b"abcd"
    assert packets[0].ts == pytest.approx(3.0)


# --------------------------------------------------------------------------- reassembly
def test_reassembly_orders_out_of_order_segments() -> None:
    # A SYN establishes the sequence base; without one the first payload byte is
    # by definition offset 0 (a mid-stream capture cannot look backwards).
    delivered: list[tuple[int, bytes]] = []
    reasm = DirectionReassembler(0, lambda _d, off, data, _ts: delivered.append((off, data)))
    reasm.push(1000, b"", 0.9, syn=True)
    reasm.push(1006, b"world", 1.0)  # arrives first, belongs after "hello"
    reasm.push(1011, b"!", 1.1)
    reasm.push(1001, b"hello", 1.2)
    assert b"".join(chunk for _off, chunk in delivered) == b"helloworld!"
    assert reasm.stats.out_of_order == 2
    assert delivered[0][0] == 0  # absolute offset of the first delivered byte


def test_reassembly_counts_retransmissions_without_duplicating() -> None:
    delivered: list[bytes] = []
    reasm = DirectionReassembler(0, lambda _d, _off, data, _ts: delivered.append(data))
    reasm.push(1000, b"abcdefgh", 1.0)
    reasm.push(1000, b"abcdefgh", 1.1)  # full retransmission
    reasm.push(1004, b"efghij", 1.2)  # partial overlap: only "ij" is new
    assert b"".join(delivered) == b"abcdefghij"
    assert reasm.stats.retransmitted == 1
    assert reasm.stats.duplicate_bytes >= 8


def test_reassembly_first_wins_on_overlap() -> None:
    delivered: list[bytes] = []
    reasm = DirectionReassembler(0, lambda _d, _off, data, _ts: delivered.append(data))
    reasm.push(100, b"AAAA", 1.0)
    reasm.push(100, b"BBBB", 1.1)  # overlap must not rewrite delivered bytes
    assert b"".join(delivered) == b"AAAA"


def test_reassembly_gap_is_skipped_after_timeout() -> None:
    delivered: list[bytes] = []
    reasm = DirectionReassembler(0, lambda _d, _off, data, _ts: delivered.append(data), gap_timeout=0.5)
    reasm.push(0, b"first", 0.0)
    reasm.push(100, b"after-gap", 0.1)
    assert reasm.maybe_skip_gap(0.2) is False
    assert reasm.maybe_skip_gap(1.0) is True
    assert b"".join(delivered) == b"firstafter-gap"
    assert reasm.gaps == [(5, 100)]


def test_reassembly_handles_sequence_wraparound() -> None:
    delivered: list[bytes] = []
    reasm = DirectionReassembler(0, lambda _d, _off, data, _ts: delivered.append(data))
    base = 0xFFFFFFF0
    reasm.push(base, b"0123456789abcdef", 1.0)  # 16 bytes crossing the 32-bit wrap
    reasm.push((base + 16) & 0xFFFFFFFF, b"XYZ", 1.1)
    assert b"".join(delivered) == b"0123456789abcdefXYZ"


# --------------------------------------------------------------------------- filters
def _pkt(**kwargs: object) -> Packet:
    pkt = Packet()
    for key, value in kwargs.items():
        setattr(pkt, key, value)
    return pkt


def test_filter_grammar_and_semantics() -> None:
    tcp_443 = _pkt(
        src="10.0.0.1",
        dst="10.0.0.2",
        sport=50000,
        dport=443,
        proto=6,
        proto_name="TCP",
        ip_version=4,
        payload_len=1200,
    )
    udp_53 = _pkt(
        src="10.0.0.3",
        dst="8.8.8.8",
        sport=5353,
        dport=53,
        proto=17,
        proto_name="UDP",
        ip_version=4,
        payload_len=40,
    )
    flt = compile_filter("tcp port 443")
    assert flt(tcp_443) and not flt(udp_53)
    assert compile_filter("udp and port 53")(udp_53)
    assert compile_filter("host 8.8.8.8")(udp_53)
    assert compile_filter("net 10.0.0.0/24")(tcp_443)
    assert not compile_filter("src host 10.0.0.9")(tcp_443)
    assert compile_filter("not udp")(tcp_443)
    assert compile_filter("len > 1000")(tcp_443)
    assert compile_filter("(tcp or udp) and not port 53")(tcp_443)
    assert compile_filter("")(udp_53)


def test_filter_rejects_nonsense_instead_of_failing_open() -> None:
    with pytest.raises(FilterSyntaxError):
        compile_filter("tcp port")
    with pytest.raises(FilterSyntaxError):
        compile_filter("frobnicate 12")
    with pytest.raises(FilterSyntaxError):
        compile_filter("tcp and (udp or")


def test_gzip_capture_is_transparently_read(tmp_path) -> None:
    from voxhound.capture.pcapfile import as_stream

    buffer = io.BytesIO()
    writer = PcapWriter(buffer, linktype=1)
    writer.write(_packets()[0])
    path = tmp_path / "capture.pcap.gz"
    path.write_bytes(gzip.compress(buffer.getvalue()))
    stream = as_stream(path)
    packets = list(PcapReader(stream))
    assert len(packets) == 1


# --------------------------------------------------------------------------- live loop
def test_capture_duration_is_honoured_under_continuous_traffic() -> None:
    """A busy link must still stop at --duration.

    Regression: the deadline used to be checked only when ``read_batch`` came
    back empty, so a constantly-busy interface ran until the traffic paused.
    """
    import time

    from voxhound.capture.source import CaptureSource
    from voxhound.engine import Engine
    from voxhound.packets import ethernet, ipv4, udp

    frame = ethernet(payload=ipv4("10.0.0.1", "10.0.0.2", 17, udp(40000, 40001, b"x" * 32)))

    class Flood(CaptureSource):
        kind = "flood"
        description = "flood"
        linktype = 1

        def __init__(self) -> None:
            self.reads = 0

        def open(self) -> None:
            pass

        def read_batch(self, max_packets: int = 512) -> list[RawPacket]:
            self.reads += 1
            return [RawPacket(ts=time.time(), data=frame, caplen=len(frame), wirelen=len(frame))]

        def close(self) -> None:
            pass

    source = Flood()
    started = time.time()
    report = Engine().run(source, duration=0.2)
    elapsed = time.time() - started
    assert elapsed < 1.0, f"duration not honoured: {elapsed:.2f}s"
    assert report.stats["packets"] > 0


def test_interface_ranking_prefers_real_adapter() -> None:
    """Wi-Fi must sort above Bluetooth and WAN Miniports."""
    from voxhound.capture.interfaces import Interface, _rank_interface

    wifi = Interface(name="wifi", description="Intel(R) Wi-Fi 6 AX201", addresses=["192.168.1.5"])
    bluetooth = Interface(name="bt", description="Bluetooth Device (PAN)", addresses=["169.254.1.2"])
    wan = Interface(name="wan", description="WAN Miniport (IP)", addresses=[])
    ordered = sorted([wan, bluetooth, wifi], key=_rank_interface)
    assert ordered[0] is wifi

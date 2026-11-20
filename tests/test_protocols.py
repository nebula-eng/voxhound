"""Protocol decoding tests: link layer through application dissectors.

Fixtures are built byte-by-byte with :mod:`voxhound.packets`, so a decoder bug
cannot be masked by a hand-written expectation that was itself wrong.
"""

from __future__ import annotations

import struct

import pytest

from voxhound.app.dns import dga_score
from voxhound.app.dns import parse as dns_parse
from voxhound.app.http2 import HpackDecoder, huffman_decode
from voxhound.app.tls import parse_client_hello, parse_server_hello, split_certificates
from voxhound.core.model import RawPacket
from voxhound.decode import Decoder
from voxhound.decode.checksum import inet_checksum
from voxhound.packets import (
    TCP_ACK,
    TCP_PSH,
    TCP_SYN,
    dns_query,
    dns_response,
    ethernet,
    http_request,
    ipv4,
    ipv6,
    tcp,
    tcp_options,
    tls_client_hello,
    tls_server_hello,
    udp,
)
from voxhound.simulate import _fake_certificate


def decode(frame: bytes, *, verify: bool = True, number: int = 1):
    decoder = Decoder(verify_checksums=verify)
    return decoder.decode(RawPacket(ts=1.0, data=frame, caplen=len(frame), wirelen=len(frame)), number)


# --------------------------------------------------------------------------- link / IP
def test_ethernet_ipv4_tcp_syn() -> None:
    frame = ethernet(
        payload=ipv4("10.0.0.1", "10.0.0.2", 6, tcp(40000, 443, 1000, 0, TCP_SYN, options=tcp_options()))
    )
    pkt = decode(frame)
    assert pkt is not None
    assert pkt.eth_src == "66:77:88:99:aa:bb"
    assert pkt.ip_version == 4
    assert (pkt.src, pkt.dst) == ("10.0.0.1", "10.0.0.2")
    assert pkt.proto_name == "TCP"
    assert pkt.sport == 40000 and pkt.dport == 443
    assert pkt.syn and not pkt.ack_flag
    assert pkt.mss == 1460 and pkt.wscale == 8
    assert "MSS" in pkt.opt_sig
    assert pkt.malformed == ""


def test_vlan_tags_are_stacked_and_parsed() -> None:
    frame = ethernet(payload=ipv4("10.0.0.1", "10.0.0.2", 17, udp(1000, 53, b"x")), vlan=42)
    pkt = decode(frame)
    assert pkt is not None
    assert pkt.vlan == (42,)
    assert pkt.proto_name == "UDP"


def test_ipv4_fragments_are_reassembled() -> None:
    payload = b"A" * 800 + b"B" * 400
    segment = udp(5000, 6000, payload, src="10.1.1.1", dst="10.1.1.2")
    first = ipv4("10.1.1.1", "10.1.1.2", 17, segment[:800], ident=0x4242, flags=0x1, frag_offset=0)
    second = ipv4("10.1.1.1", "10.1.1.2", 17, segment[800:], ident=0x4242, flags=0x0, frag_offset=800)
    decoder = Decoder()
    part1 = decoder.decode(RawPacket(1.0, ethernet(payload=first), len(first) + 14, len(first) + 14), 1)
    assert part1 is not None and part1.frag and "offset=" in part1.frag
    part2 = decoder.decode(RawPacket(1.1, ethernet(payload=second), len(second) + 14, len(second) + 14), 2)
    assert part2 is not None
    assert part2.frag == "reassembled"
    assert part2.payload_len == len(payload)


def test_ipv6_extension_chain_and_address_format() -> None:
    inner = udp(5353, 53, b"hello", src="2001:db8::10", dst="2001:db8::53")
    frame = ethernet(ethertype=0x86DD, payload=ipv6("2001:db8::10", "2001:db8::53", 17, inner))
    pkt = decode(frame)
    assert pkt is not None
    assert pkt.ip_version == 6
    assert pkt.src == "2001:db8::10" and pkt.dst == "2001:db8::53"
    assert pkt.proto_name == "UDP"


def test_checksum_verification_flags_corruption() -> None:
    frame = bytearray(
        ethernet(payload=ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1234, 80, 1, 0, TCP_ACK, b"payload")))
    )
    frame[14 + 10] ^= 0xFF  # corrupt the IPv4 checksum field
    pkt = decode(bytes(frame), verify=True)
    assert pkt is not None
    assert "checksum" in pkt.malformed


def test_truncated_frame_is_reported_not_raised() -> None:
    pkt = decode(b"\x00\x11\x22")
    assert pkt is not None
    assert "malformed" in pkt.info.lower()


# --------------------------------------------------------------------------- TCP
def test_tcp_payload_and_flags() -> None:
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    frame = ethernet(
        payload=ipv4("10.0.0.1", "10.0.0.2", 6, tcp(50000, 80, 10, 20, TCP_ACK | TCP_PSH, payload))
    )
    pkt = decode(frame)
    assert pkt is not None
    assert bytes(pkt.payload) == payload
    assert pkt.payload_len == len(payload)
    assert "AP" in pkt.info


# --------------------------------------------------------------------------- DNS
def test_dns_query_and_response_roundtrip() -> None:
    query = dns_parse(dns_query("api.example.com"))
    assert query.questions[0].name == "api.example.com."
    assert not query.is_response

    response = dns_parse(dns_response("api.example.com", [(1, bytes([93, 184, 216, 34]))]))
    assert response.is_response
    assert response.answers[0].data == "93.184.216.34"


def test_dns_compression_pointer_loop_is_rejected() -> None:
    header = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    # name that points at itself
    malformed = header + b"\xc0\x0c"
    from voxhound.app.dns import DnsError

    with pytest.raises(DnsError):
        dns_parse(malformed)


def test_dga_scores_algorithmic_names_higher_than_words() -> None:
    assert dga_score("k7fq2x9z3m1p8r4t6v0y.cn") > 0.55
    assert dga_score("mail.google.com") < 0.3


# --------------------------------------------------------------------------- TLS
def test_client_hello_fields_and_ja4_shape() -> None:
    # 5-byte TLS record header + 4-byte handshake header, then the body
    hello = parse_client_hello(tls_client_hello("secure.example.org")[9:])
    assert hello.sni == "secure.example.org"
    assert hello.alpn[0] == "h2"
    assert max(hello.versions) == 0x0304
    assert 0x1301 in hello.ciphers


def test_server_hello_and_certificate_split() -> None:
    server = parse_server_hello(tls_server_hello(0x1302)[9:])
    assert server.cipher == 0x1302
    assert server.version == 0x0304

    cert = _fake_certificate("api.example.com", "Test CA", sans=("api.example.com",))
    body = b"\x00" + (len(cert) + 3).to_bytes(3, "big") + len(cert).to_bytes(3, "big") + cert
    parts = split_certificates(body, tls13=True)
    assert parts and parts[0] == cert


# --------------------------------------------------------------------------- HTTP / HPACK
def test_chunked_response_survives_tcp_segmentation() -> None:
    """A chunk split across segments must not be mistaken for Content-Length.

    This regressed once: after a partial chunk the parser reused the chunk size
    as a byte count, completed the message early and carved a truncated body.
    """
    from voxhound.app.http1 import Http1Dissector
    from voxhound.simulate import http_response

    payload = bytes(range(256)) * 10  # 2560 bytes, deliberately not chunk-aligned

    chunked = b""
    for start in range(0, len(payload), 300):
        piece = payload[start : start + 300]
        chunked += f"{len(piece):x}\r\n".encode() + piece + b"\r\n"
    chunked += b"0\r\n\r\n"

    response = http_response(
        200,
        "OK",
        headers={"Content-Type": "application/octet-stream", "Transfer-Encoding": "chunked"},
        body=chunked,
    )

    class Flow:
        http_hosts: list[str] = []
        user_agents: list[str] = []
        src = "10.0.0.1"
        dst = "10.0.0.2"

    class Sink:
        def __init__(self) -> None:
            self.flow = Flow()
            self.artifacts: list[tuple[str, bytes, dict]] = []

        def emit(self, *args: object, **kwargs: object) -> None:
            pass

        def tag(self, *args: object, **kwargs: object) -> None:
            pass

        def note(self, *args: object, **kwargs: object) -> None:
            pass

        def artifact(self, kind: str, name: str, data: bytes, **meta: object) -> None:
            self.artifacts.append((kind, data, meta))

    sink = Sink()
    dissector = Http1Dissector(sink)  # type: ignore[arg-type]
    for offset in range(0, len(response), 700):
        dissector.feed(1, response[offset : offset + 700])
    dissector.close()

    assert sink.artifacts, "chunked body was never carved"
    _kind, data, meta = sink.artifacts[0]
    assert data == payload
    assert meta["truncated"] is False


def test_http_request_line_is_parsed_by_decoder() -> None:
    request = http_request("POST", "/login", "example.com", headers={"Content-Length": "4"}, body=b"a=1&")
    frame = ethernet(
        payload=ipv4("10.0.0.1", "10.0.0.2", 6, tcp(12345, 80, 1, 1, TCP_ACK | TCP_PSH, request))
    )
    pkt = decode(frame)
    assert pkt is not None
    assert pkt.payload_len == len(request)


def test_hpack_static_table_and_literal_decoding() -> None:
    decoder = HpackDecoder()
    # 0x82 = indexed :method GET, 0x86 = :scheme http
    headers = decoder.decode(bytes([0x82, 0x86]))
    assert headers == [(":method", "GET"), (":scheme", "http")]

    literal = bytes([0x40, 0x04]) + b"path" + bytes([0x05]) + b"/api1"
    decoded = decoder.decode(literal)
    assert decoded == [("path", "/api1")]
    # adding to the dynamic table shifts later indices: index 62 is the newest entry
    assert decoder.lookup(62) == ("path", "/api1")


def test_huffman_table_is_a_valid_prefix_code() -> None:
    from voxhound.app._hpack_huffman import HUFFMAN_CODES

    assert len(HUFFMAN_CODES) == 257
    kraft = sum(2.0 ** (-bits) for _code, bits in HUFFMAN_CODES)
    assert abs(kraft - 1.0) < 1e-9, "Huffman code lengths must satisfy Kraft equality"
    assert HUFFMAN_CODES[256] == (0x3FFFFFFF, 30)  # EOS is 30 one-bits


def test_huffman_roundtrip_using_the_generated_table() -> None:
    from voxhound.app._hpack_huffman import HUFFMAN_CODES

    text = b"www.example.com/no-cache"
    accumulator = 0
    bits = 0
    payload = bytearray()
    for byte in text:
        code, length = HUFFMAN_CODES[byte]
        accumulator = (accumulator << length) | code
        bits += length
        while bits >= 8:
            bits -= 8
            payload.append((accumulator >> bits) & 0xFF)
    if bits:
        payload.append(((accumulator << (8 - bits)) | ((1 << (8 - bits)) - 1)) & 0xFF)
    assert huffman_decode(bytes(payload)) == text


# --------------------------------------------------------------------------- WebSocket
class _Sink:
    """Minimal AppSession stand-in: records events, artifacts, tags and notes."""

    def __init__(self) -> None:
        from voxhound.app.base import AppSession

        class Flow:
            def __init__(self) -> None:
                self.tags: list[str] = []
                self.notes: dict[str, object] = {}

        self.flow = Flow()
        self.events: list[object] = []
        self.artifacts: list[object] = []
        self.session = AppSession(
            self.flow, None, event_sink=self.events.append, artifact_sink=self.artifacts.append
        )

    @property
    def titles(self) -> list[str]:
        return [str(event.title) for event in self.events]


def _ws_frame(payload: bytes, opcode: int = 1, *, fin: bool = True) -> bytes:
    head = bytes([(0x80 if fin else 0) | opcode])
    size = len(payload)
    if size < 126:
        head += bytes([0x80 | size])
    elif size < 65536:
        head += bytes([0x80 | 126]) + struct.pack("!H", size)
    else:
        head += bytes([0x80 | 127]) + struct.pack("!Q", size)
    mask = b"\x01\x02\x03\x04"
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def test_websocket_reassembles_fragments() -> None:
    from voxhound.app.websocket import WebSocketDissector

    sink = _Sink()
    dissector = WebSocketDissector(sink.session)
    dissector.feed(0, _ws_frame(b"hello ", fin=False))
    dissector.feed(0, _ws_frame(b"world", opcode=0))
    assert sink.titles[-1].endswith("hello world")


def test_websocket_flags_orphan_continuation() -> None:
    from voxhound.app.websocket import WebSocketDissector

    sink = _Sink()
    dissector = WebSocketDissector(sink.session)
    dissector.feed(0, _ws_frame(b"orphan", opcode=0))
    assert "continuation without a start frame" in sink.titles[-1]


def test_websocket_recognises_base64_audio_text() -> None:
    """Browsers wrap Opus/SILK in a base64 text frame starting with ``AA``."""
    import base64

    from voxhound.app.websocket import WebSocketDissector

    sink = _Sink()
    dissector = WebSocketDissector(sink.session)
    payload = b"AA" + base64.b64encode(b"\x01" * 120)
    dissector.feed(0, _ws_frame(payload))
    assert "ws-base64-audio?" in sink.flow.tags
    assert sink.flow.notes["ws_audio_text"] == len(payload)


# --------------------------------------------------------------------------- MQTT
def _mqtt_frame(ptype: int, flags: int, body: bytes) -> bytes:
    size = len(body)
    out = bytearray([(ptype << 4) | flags])
    while True:
        byte = size % 128
        size //= 128
        out.append(byte | (0x80 if size else 0))
        if not size:
            break
    return bytes(out) + body


def test_mqtt_survives_truncated_connect() -> None:
    """A bogus protocol-name length must not raise out of the dissector."""
    from voxhound.app.mqtt import MqttDissector

    sink = _Sink()
    body = struct.pack("!H", 40) + b"MQTT" + b"\x04\x02" + b"\x00\x3c"
    MqttDissector(sink.session).feed(0, _mqtt_frame(1, 0, body))
    assert "truncated CONNECT" in sink.titles[-1]


def test_mqtt_publish_qos1_skips_packet_id() -> None:
    from voxhound.app.mqtt import MqttDissector

    sink = _Sink()
    topic = b"a/b"
    payload = b"hello world"
    body = struct.pack("!H", len(topic)) + topic + b"\x00\x01" + payload
    MqttDissector(sink.session).feed(0, _mqtt_frame(3, 0x02, body))
    assert sink.events[-1].detail["bytes"] == len(payload)


def test_mqtt_remaining_length_split_across_segments() -> None:
    from voxhound.app.mqtt import MqttDissector

    sink = _Sink()
    body = b"\x00\x01x" + b"y" * 200
    frame = _mqtt_frame(3, 0, body)
    dissector = MqttDissector(sink.session)
    dissector.feed(0, frame[:2])  # length varint ends mid-way
    dissector.feed(0, frame[2:])
    assert sink.events and sink.events[-1].detail["bytes"] == 200


def test_mqtt_client_id_stays_out_of_http_hosts() -> None:
    from voxhound.app.mqtt import MqttDissector

    sink = _Sink()
    body = struct.pack("!H", 4) + b"MQTT" + b"\x04\x02\x00\x3c" + struct.pack("!H", 3) + b"dev"
    MqttDissector(sink.session).feed(0, _mqtt_frame(1, 0, body))
    assert not hasattr(sink.flow, "http_hosts") or not sink.flow.http_hosts
    assert sink.flow.notes["mqtt_client_id"] == "dev"


# --------------------------------------------------------------------------- STUN
def test_stun_ipv4_xor_mapped_address_rfc5769_vector() -> None:
    from voxhound.app.stun import MAGIC_COOKIE, parse_stun

    txid = bytes.fromhex("b7e7a701bc34d686fa87dfae")
    attr = bytes.fromhex("00200008") + bytes.fromhex("0001a147e112a643")
    message = struct.pack("!HHI", 0x0101, len(attr), MAGIC_COOKIE) + txid + attr
    assert parse_stun(message)["xor_mapped"] == "192.0.2.1:32853"


def test_stun_ipv6_xor_uses_transaction_id() -> None:
    """RFC 5389 masks IPv6 with ``cookie || transaction-id``, not the cookie alone."""
    from voxhound.app.stun import MAGIC_COOKIE, parse_stun

    txid = bytes.fromhex("b7e7a701bc34d686fa87dfae")
    address = bytes.fromhex("20010db8123456780011002233445566")
    port = 49152
    mask = struct.pack("!I", MAGIC_COOKIE) + txid
    xored = bytes(a ^ b for a, b in zip(address, mask))
    value = struct.pack("!BBH", 0, 2, port ^ (MAGIC_COOKIE >> 16)) + xored
    attr = struct.pack("!HH", 0x0020, len(value)) + value
    message = struct.pack("!HHI", 0x0101, len(attr), MAGIC_COOKIE) + txid + attr
    assert parse_stun(message)["xor_mapped"] == "[2001:0db8:1234:5678:0011:0022:3344:5566]:49152"


# --------------------------------------------------------------------------- misc
def test_inet_checksum_of_valid_header_is_zero() -> None:
    header = ipv4("192.0.2.1", "198.51.100.7", 17, b"", ttl=64, ident=1)
    assert inet_checksum(header) == 0

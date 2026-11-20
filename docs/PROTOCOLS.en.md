# Protocol coverage

> 中文版：[PROTOCOLS.md](PROTOCOLS.md)。本文件为英文归档，可能滞后。

What VoxHound parses, what it merely identifies, and where the edges are. If a
protocol is not listed as *decoded*, assume it is carried as opaque bytes.

## Link layer

| Link type | Status | Notes |
|---|---|---|
| Ethernet (1) | decoded | stacked 802.1Q / 802.1ad tags preserved in `Packet.vlan` |
| Linux cooked v1 / v2 (113/276) | decoded | `tcpdump -i any` captures |
| BSD loopback / NULL (0) | decoded | family auto-detected |
| Raw IP (101), IPv4 (228), IPv6 (229) | decoded | |
| MPLS (0x8847/0x8848) | unwrapped | label stack walked to bottom-of-stack |
| PPPoE session (0x8864) | unwrapped | PPP protocol → IPv4/IPv6 |
| 802.3 LLC/SNAP | decoded | else treated as opaque |
| 802.11 / radiotap (105/127) | not supported | monitor-mode Wi-Fi is out of scope |

## Network layer

| Protocol | Status | Details |
|---|---|---|
| IPv4 | decoded | options parsed, header checksum optional, fragmentation reassembled (first-wins, 30 s, 4 096 datagrams) |
| IPv6 | decoded | extension chains (HopByHop, Routing, Fragment, DestOpts) walked; fragment reassembly |
| ARP | decoded | request/reply, sender/target addresses |
| ICMP / ICMPv6 | decoded | echo, unreachable, time exceeded, PTB |
| GRE / ESP / AH | identified | payload not decoded (ESP is encrypted by definition) |

## Transport layer

| Protocol | Status | Details |
|---|---|---|
| TCP | decoded | full option parsing (MSS, WS, SACK, timestamps, TFO), option-order signature, flags, out-of-order reassembly, retransmission and duplicate accounting, gap detection, 32-bit wraparound |
| UDP | decoded | length-bounded payload |
| SCTP | identified | not reassembled |
| QUIC | see below | UDP-based, long/short header detection |

## Application layer

### TLS (TCP)

| Item | Status |
|---|---|
| ClientHello: SNI, ALPN, versions, cipher suites, extensions, groups, signature algorithms | decoded |
| ServerHello: chosen version, cipher, ALPN | decoded |
| Certificate chain: subject, issuer, CN/O, SANs, validity, signature algorithm | decoded (structural DER walk, no signature validation) |
| JA3, JA4, JA4S | computed |
| Alerts (close_notify, handshake_failure, unrecognized_name…) | decoded |
| Encrypted application data | counted only (sizes, direction) |
| TLS 1.3 record decryption | not implemented (see roadmap: SSLKEYLOGFILE) |

### QUIC

| Item | Status |
|---|---|
| Long header: version, DCID, SCID, token, packet number | decoded |
| Initial packet decryption (RFC 9001 keys from DCID) | decoded - up to 6 Initials / 8 KiB per flow |
| CRYPTO frames → TLS ClientHello → SNI, ALPN, JA4Q | decoded |
| ServerHello in server Initial | decoded |
| 0-RTT / Handshake / 1-RTT | identified, counted, not decrypted |
| Version negotiation, Retry | identified |

### HTTP

| Item | Status |
|---|---|
| HTTP/1.0–1.1 request/response line and headers | decoded |
| `Content-Length`, `Transfer-Encoding: chunked`, trailers | decoded |
| Pipelined requests on one connection | decoded (per-direction state) |
| Upgrade → WebSocket | detected, switches dissector |
| Body carving with magic-byte type sniffing | decoded |
| HTTP/2 (h2c preface) frames: HEADERS, CONTINUATION, DATA, SETTINGS, PING, GOAWAY, RST_STREAM | decoded |
| HPACK: static table, dynamic table, integer/string, Huffman | decoded |
| HTTP/2 over TLS | not decoded (encrypted) |

### WebSocket

Frames (text, binary, close, ping, pong), masking, fragmentation, message
reassembly. Base64-wrapped payloads larger than 8 KiB are decoded and carved.

### DNS

| Item | Status |
|---|---|
| Header, questions, answers, authority, additional | decoded |
| Name compression pointers (with loop guard) | decoded |
| A, AAAA, CNAME, NS, PTR, MX, TXT, SOA, SRV, SVCB/HTTPS | decoded |
| EDNS0 / OPT | identified via additional section |
| DGA heuristic on query labels | computed |
| DNS over TCP (2-byte length prefix) | decoded |
| DoH / DoT | inside TLS - metadata only |

### Voice and media

| Item | Status |
|---|---|
| RTP header, CSRC list, extension header, padding | decoded |
| RTP reordering (256-packet window), RFC 3550 jitter, loss, duplicates | computed |
| G.711 µ-law / A-law → 16-bit PCM → WAV | decoded, exported |
| Opus / G.722 / AAC payloads | exported raw with timing metadata (no decoder) |
| RTCP SR/RR/SDES/BYE | identified and counted |
| SIP: request/response lines, Call-ID, From/To, User-Agent, SDP `m=`/`c=`/`rtpmap` | decoded |
| SDP → RTP port correlation | recorded on the flow, not auto-joined |
| RTMP handshake | identified |

### Infrastructure protocols

| Protocol | Status |
|---|---|
| STUN: binding requests/responses, USERNAME, SOFTWARE, XOR-MAPPED-ADDRESS | decoded |
| MQTT 3.1.1/5.0: CONNECT, CONNACK, PUBLISH, SUBSCRIBE | decoded |
| SSH, FTP, SMTP, POP3, IMAP, Redis, RTMP | banner/identification |

## Known limits

1. Reassembly starts at the first captured byte. A capture that begins
   mid-connection cannot recover earlier bytes.
2. Only the first 64 KiB of each non-HTTP stream is scanned for embedded
   files. Carving large media out of an arbitrary TCP stream is a separate
   problem (see roadmap).
3. Checksums are validated only when `--verify-checksums` is passed; live
   capture skips it to keep the CPU for reassembly.
4. No IP reassembly across VLAN or tunnel boundaries, and no tunnel
   decapsulation beyond MPLS/PPPoE.
5. Encrypted payloads are counted, never inspected - except QUIC Initial,
   whose keys are part of the protocol.

# Architecture

This document explains why the code is shaped the way it is. When you review a patch, these are the invariants it has to keep.

Chinese version: [ARCHITECTURE.md](ARCHITECTURE.md). This file can lag behind it.

## 1. Layering

```
voxhound/
├── core/          model, util, ring buffers, event bus        (no imports upward)
├── capture/       sources + pcap/pcapng IO + BPF subset
├── decode/        link, IPv4/IPv6, TCP/UDP/ICMP, fragments
├── app/           stream & datagram dissectors (TLS, HTTP, DNS, QUIC, RTP…)
├── flows/         TCP reassembly, flow table, behavioural analysis
├── media/         WAV/G.711, RTP call reconstruction, magic-byte carving
├── intel/         JA3/JA4/JA4S/JA4T, X.509, OS hints
├── crypto/        pure-Python AES-GCM + HKDF (QUIC Initial)
├── rules/         declarative JSON detections + engine
├── store/         SQLite session persistence
├── export/        HTML/Markdown reports, filtered pcap, NDJSON, CSV
├── engine.py      the pipeline that connects all of the above
├── cli.py         argparse front-end
└── ui/            PySide6 desktop shell (the only optional part)
```

Dependencies point downward only. `core` imports nothing from the project; `ui` may import anything; nothing imports `ui`.

Hard rule: `voxhound/` outside `ui/` must run on a bare interpreter. CI enforces it two ways: the suite runs where pytest is the only third-party package installed, and an AST pass rejects any import outside the standard library. One stray dependency turns the build red.

## 2. Data flow

```
RawPacket ──► Decoder ──► Filter ──► FlowManager ──► dissectors
                │                        │
                │                        ├─► AppEvent   ──► rules ──► Alert
                │                        ├─► Artifact   (bounded budget)
                │                        └─► heuristics ──► Alert
                └─ malformed? keep going, annotate
```

One packet can produce zero or more events and artifacts. Nothing is stored unless the caller asked for it: the engine's default is to keep counters, flows, events (ring) and artifacts (budgeted), not packets.

## 3. Invariants

### 3.1 `Packet.payload` is a `memoryview`, and must not escape

The decoder slices into the capture buffer instead of copying. That is what makes a 4 GiB pcap stream in constant memory. Anything that stores payload bytes must copy them (`bytes(view)`) at the boundary; the reassembler does exactly this.

### 3.2 A dissector bug must not kill the capture

`FlowManager._tcp` wraps dissector dispatch in `try/except`: a crash drops the dissector for that flow, tags the flow `dissector-error`, and increments `dissector_errors`. Hostile input is the normal case for a forensics tool.

### 3.3 Memory is bounded everywhere

| Structure | Bound |
|---|---|
| Packet ring (UI) | 20 000 rows |
| Flow table | `max_flows` (120 k default) with LRU eviction preferring closed flows |
| Out-of-order TCP buffer | 8 MiB per direction, 256 segments drained under pressure |
| Stream preview | 64 KiB per direction |
| Artifact budget | 256 MiB (engine) / 512 MiB (UI worker) |
| Fragment tables | 4 096 datagrams, 30 s expiry, 64 KiB max datagram |
| HPACK dynamic table | 4 096 bytes (protocol-defined) |
| Event ring | 5 000 |

### 3.4 The engine never touches Qt; the UI never touches the engine's state

The UI receives immutable snapshots (`dict`, `list[tuple]`) through queued signals. There is no shared mutable object between the capture thread and the GUI thread, therefore no locks in the hot path.

## 4. TCP reassembly

Implemented in `flows/stream.py`. The decisions that matter:

Sequence arithmetic. Absolute offsets are a signed 32-bit delta from the direction's ISN:

```python
rel = ((seq - isn + 0x80000000) & 0xFFFFFFFF) - 0x80000000
```

That gives ±2 GiB of unambiguous window and is immune to the 4 GiB wraparound that breaks "last_seq + delta" accumulators.

Overlap policy is first-wins. Delivered bytes are never rewritten. This matches BSD behaviour and defeats the classic IDS evasion of retransmitting an overlapping segment to rewrite already-parsed content.

Gaps. If a hole does not fill within `gap_timeout` (2 s), the reassembler records it and jumps forward. One lost packet must not stall a conversation. Gaps are propagated to the application layer so artifacts can be marked truncated rather than silently corrupt.

Sequence base without a SYN. A capture that starts mid-connection has no ISN; the first payload byte becomes offset 0. Looking backwards is impossible, and the code says so instead of guessing.

## 5. Dissector selection

Content first, ports second, in `app/registry.py`.

Ports get it wrong: TLS on 8443, HTTP on 8080, SIP on 5060 and 5080, and anything at all on 443. The first bytes of a stream are much harder to fake:

| Sniff | Dissector |
|---|---|
| `0x16 0x03` | TLS |
| `PRI * HTTP/2.0` | HTTP/2 (h2c) |
| `GET `/`POST`/`HEAD`… | HTTP/1.1 |
| `SSH-` | banner |
| Content-Type / magic | carving |

The UDP path has an ordering subtlety worth knowing: RTP is checked before QUIC, because both start with a high bit set. Getting that order wrong sends every voice call into the QUIC parser. It happened during development and is now covered by the demo's RTP scenario.

## 6. QUIC Initial decryption

`app/quic.py` and `crypto/`.

1. Parse the invariant long header (version, DCID, SCID, token, length).
2. Derive initial secrets: `HKDF-Extract(salt_version, DCID)` then `HKDF-Expand-Label(…, "client in"/"server in")` to key/iv/hp.
3. Nonce = `iv XOR packet_number`; AAD = the header up to and including the PN.
4. `AES-128-GCM` open; try client keys, then server keys.
5. Walk frames for `CRYPTO`, reassemble by offset, parse the TLS ClientHello.

Correctness is anchored in `tests/test_crypto.py` (FIPS-197 AES vectors, NIST GCM vectors, RFC 5869 HKDF vectors, RFC 9001 initial keys) and in the demo scenario, which encrypts a real ClientHello with the RFC 9001 derivation. If either the crypto or the framing is off by a byte, the SNI never appears and `tests/test_engine.py` fails.

Cost control: at most 6 Initials and 8 KiB per flow are decrypted. Pure-Python AES-GCM is fast enough for handshakes and far too slow for bulk traffic.

## 7. HPACK

`app/http2.py` implements the full decoder: static table (61 entries), dynamic table with eviction, integer/string primitives and the canonical Huffman code.

The Huffman table is generated, not typed: `scripts/gen_hpack_huffman.py` parses RFC 7541 Appendix B and writes `app/_hpack_huffman.py`. A 257-entry table pasted by hand is a transcription bug waiting to happen; a generator plus a Kraft equality test plus a round-trip encode/decode test is a table you can trust.

## 8. Fingerprints

- JA4 (`intel/ja4.py`): `t13d1516h2_…`. GREASE excluded everywhere, version from `supported_versions`, cipher hash sorted, extension hash with SNI/ALPN removed and signature algorithms appended in wire order. The published Chrome cipher hash (`8daaf6152771`) is a test vector.
- JA4S: server counterpart with the chosen cipher.
- JA3: legacy MD5, kept because blocklists still use it.
- JA4T: `window_options_mss_wscale` from the SYN.
- OS hint (`intel/p0f.py`): option-order signatures with a confidence band, not a p0f clone; it returns "Windows (likely)" instead of false precision.

## 9. Behavioural analysis

`flows/anomaly.py`. Each detector is small, stateful and capped:

- Scan: SYN-only, distinct destination ports per (src, dst) within a window.
- Beacon: coefficient of variation of inter-arrival times ≤ 0.18 with ≥ 6 samples. Scale-free by construction, so it does not care whether the interval is 5 seconds or 5 hours.
- Tunnel: ≥ 40 distinct subdomains under one parent.
- Exfil: outbound/inbound ratio ≥ 20 above a 2 MiB floor.

Thresholds are constructor arguments rather than constants, because they are policy choices.

## 10. Reports and persistence

`export/report.py` writes one self-contained HTML file: inline CSS, inline SVG charts (donut, area, bars), no network requests. Analysts paste these into tickets and read them on air-gapped machines.

`store/sqlite.py` stores metadata and hashes, never payload bytes. A multi-gigabyte voice dump has no business inside a transaction log.

## 11. Threading model

```
main thread (Qt)                worker thread
────────────────                ─────────────
MainWindow                      EngineWorker.run()
  ├─ models                       └─ Engine.run(source)
  ├─ pages                             ├─ on_packet  ─┐
  └─ CaptureController ◄── queued signals ────────────┘
```

`CaptureController` owns a `QThread` and an `EngineWorker`. Callbacks buffer their items and emit batches (`PACKET_FLUSH = 48`, or every 120 ms), so the GUI never sees a signal per packet. Stopping is a cooperative `threading.Event`; the source is closed on the way out.

## 12. Testing strategy

- Byte-level fixtures. Packets are built with `voxhound.packets`, so a decoder bug cannot hide behind a hand-written expectation.
- The demo is a fixture. `voxhound.simulate` produces a real capture with TLS, h2c, WebSocket, a G.711 call, a QUIC Initial and a port scan. End-to-end tests assert content: the SNI inside the encrypted QUIC packet, a playable WAV, the beacon finding.
- Vectors over impressions. FIPS-197 and NIST GCM vectors for crypto; the FoxIO Chrome cipher hash for JA4; Kraft equality for the Huffman table.
- No mocks in the pipeline. The UI is excluded from coverage on purpose; the engine is expected to be testable without it.

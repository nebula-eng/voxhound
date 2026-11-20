# Command line reference

> 中文版：[CLI.md](CLI.md)。本文件为英文归档，可能滞后。

```
voxhound <command> [options]
```

| Command | Purpose |
|---|---|
| `demo` | full simulated session - no privileges, no network needed |
| `analyze FILE` | offline analysis of a `.pcap` / `.pcapng` / gzip capture |
| `sniff -i IFACE` | live capture (Npcap/libpcap, or Linux AF_PACKET) |
| `extract FILE -o OUT` | write frames matching a filter into a new pcap |
| `interfaces` | list capture interfaces and the backend in use |
| `rules [--check PATH]` | list rules, validate a rule file/directory |
| `gui [SPEC]` | launch the desktop application |
| `version` | version, Python, platform, libpcap status |

## Output options (analyze / sniff / demo)

| Option | Writes |
|---|---|
| `--report REPORT.html` | self-contained HTML report (inline CSS + SVG, no network) |
| `--markdown FILE.md` | compact Markdown summary for tickets and PRs |
| `--json FILE` | full report as JSON (flows, events, alerts, artifacts, hosts) |
| `--ndjson FILE` | one JSON object per event - for log pipelines |
| `--csv FILE` | flow table as CSV |
| `--store FILE.db` | SQLite session (flows, events, alerts, artifact metadata) |
| `--artifacts DIR` | carved payloads written to disk (WAV, images, documents) |
| `-w, --write FILE.pcap` | mirror captured frames into a pcap while analysing |
| `--rules PATH` | additional rule file or directory |
| `--no-rules` / `--no-heuristics` | disable built-in rules / behavioural detectors |
| `--quiet` | no progress output |

## `analyze`

```bash
voxhound analyze capture.pcapng \
  --filter "tcp port 443" \
  --verify-checksums \
  --report report.html --store session.db --artifacts carved/
```

| Option | Meaning |
|---|---|
| `--filter EXPR` | BPF-style filter subset (see below) |
| `--verify-checksums` | validate IPv4/TCP/UDP checksums (slower) |
| `--replay --speed N` | replay the file at wire pace (useful to demo a live run) |

## `sniff`

```bash
sudo voxhound sniff -i eth0 --filter "udp" --duration 60 -w live.pcap --report live.html
```

| Option | Meaning |
|---|---|
| `-i, --interface` | interface name (`voxhound interfaces` lists them) |
| `--snaplen` | snapshot length in bytes (default 262144) |
| `--buffer-mb` | kernel capture buffer (default 16) |
| `--no-promisc` | do not request promiscuous mode |
| `--raw-socket` | Linux only: AF_PACKET instead of libpcap (needs `CAP_NET_RAW`) |
| `--duration` | stop after N seconds (Ctrl-C also stops cleanly) |

## `demo`

```bash
voxhound demo --demo-duration 30 --speed 2 --seed 7 --report demo.html --artifacts out/
```

Generates deterministic traffic (TLS, h2c, WebSocket, a G.711 call, a QUIC
Initial, a port scan, a beacon) and runs the full pipeline over it. Same `--seed`
produces byte-identical traffic - useful for regression comparisons.

## `extract`

```bash
voxhound extract big.pcap -o tls.pcap --filter "tcp port 443" --limit 5000
```

A second pass over the file: frames are decoded, matched, and written
byte-identically. Constant memory, works on captures larger than RAM.

## Filters

A strict subset of libpcap syntax - the same string works for the kernel filter
(live) and the Python predicate (files):

```
tcp | udp | icmp | icmp6 | arp | ip | ip6
[src|dst] host 10.0.0.1
[src|dst] net 10.0.0.0/8
[src|dst] port 443 | portrange 8000-8100
len > 1000 | contains "SILK"
not X | X and Y | X or Y | ( X )
```

`tcp port 443` works without `and` (implicit AND), like tcpdump. Anything outside
the grammar is rejected with a caret - a filter that silently matches everything
is worse than an error.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | completed, no high-severity findings |
| `1` | completed with high-severity findings |
| `2` | completed with critical findings |
| `3` | usage error, missing file, or capture source unavailable |
| `130` | interrupted (Ctrl-C) |

## Environment

| Variable | Effect |
|---|---|
| `NO_COLOR` | disable ANSI colour in CLI output |

## Examples for CI

```bash
# Fail the build when critical findings appear in a nightly capture
voxhound analyze nightly.pcap --quiet --report nightly.html --json nightly.json || exit $?

# Convert and normalise whatever the sensor wrote
voxhound analyze sensor.pcapng --write normalised.pcap --report sensor.html --quiet
```

# Rule reference

> 中文版：[RULES.md](RULES.md)。本文件为英文归档，可能滞后。

Rules are JSON. No DSL parser, no YAML indentation traps, no regex engine to
audit - just a flat `match` object that is easy to review, diff and generate.

## File shape

A rule file is either a bare array of rules or an object with a `rules` array:

```json
{
  "version": 1,
  "rules": [
    {
      "id": "tls-no-sni",
      "name": "TLS handshake without SNI",
      "severity": 2,
      "scope": "event",
      "description": "Client connected without a server name.",
      "match": { "kind": "tls", "tag_any": ["no-sni"] },
      "tags": ["evasion"],
      "mitre": "T1090",
      "enabled": true
    }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | stable identifier; appears in alerts and the report |
| `name` | no | human title (defaults to `id`) |
| `severity` | no | `0` info, `1` low, `2` medium, `3` high, `4` critical (default `2`) |
| `scope` | no | `event` (default) or `flow` |
| `description` | no | shown in the UI and the report |
| `match` | yes | conditions, all ANDed |
| `tags` | no | free-form labels |
| `mitre` | no | ATT&CK technique, shown in the UI |
| `enabled` | no | default `true` |

## When rules run

* `scope: "event"` - every time a dissector emits an event (a DNS query, a
  TLS ClientHello, an HTTP response…). The event is evaluated with its flow
  context, so both event and flow fields are in scope.
* `scope: "flow"` - once, when the flow closes (or at end of capture), with
  totals available: bytes, duration, ports, app, tags, notes.

## Condition reference

### Event conditions

| Key | Type | Matches when |
|---|---|---|
| `kind` | string or array | event kind is one of (`dns`, `tls`, `http`, `h2`, `ws`, `quic`, `rtp`, `sip`, `stun`, `mqtt`, `banner`) |
| `title_contains` | string | case-insensitive substring of the event title |
| `title_regex` | string | regex (case-insensitive) against the event title |
| `not_title_regex` | string | regex must not match |
| `severity_gte` | int | event severity at least this value |
| `detail` | object | `{key: substring}` - each key's value must contain the substring (case-insensitive) |

### Flow conditions (available to both scopes when a flow is present)

| Key | Type | Matches when |
|---|---|---|
| `sni_regex` | string | flow SNI matches (empty SNI never matches a non-empty regex) |
| `ja4_regex` | string | flow JA4 matches |
| `dns_regex` | string | any DNS name seen on the flow matches |
| `ip_regex` | string | `"src dst"` matches |
| `port` | int | either endpoint port equals |
| `port_in` | array | either endpoint port is in the list |
| `proto` | string | `TCP`, `UDP`, `ICMP`, … |
| `app_in` | array | flow's app is one of (`TLS`, `HTTP`, `DNS`, `QUIC`, `RTP`, …) |
| `tag_any` | array | flow carries at least one of these tags |
| `note_true` | object | `{key: true}` - flow note is truthy |

### Flow-only totals

| Key | Type | Matches when |
|---|---|---|
| `bytes_gt` | int | flow payload bytes greater than |
| `duration_gt` | float | flow duration (seconds) greater than |

## Tags you can match on

Set by dissectors and the flow layer:

`no-sni`, `ech`, `session-resumption`, `self-signed-cert`, `expired-cert`,
`cert-expiring`, `cert-hostname-mismatch`, `sni-rejected`, `http-4xx`,
`http-5xx`, `websocket`, `ws-closed`, `dga?`, `dns-truncated`, `quic`,
`quic-handshake`, `rtp`, `voice-g711`, `webrtc`, `voip-signalling`, `call-ended`,
`ssh`, `mqtt`, `dissector-error`.

## Examples

Cleartext credentials over HTTP - flags a POST carrying an Authorization
header:

```json
{
  "id": "http-cleartext-auth",
  "name": "Credentials over cleartext HTTP",
  "severity": 3,
  "match": { "kind": "http", "detail": { "auth": "true" } }
}
```

Suspicious certificate for a specific estate:

```json
{
  "id": "corp-cert-allowlist",
  "name": "Unexpected certificate issuer",
  "severity": 2,
  "scope": "event",
  "match": { "kind": "tls", "title_regex": "^certificate", "title_contains": "issuer=Evil CA" }
}
```

Bulk upload to an unknown host:

```json
{
  "id": "bulk-upload",
  "name": "Large outbound transfer over an encrypted or HTTP session",
  "severity": 3,
  "scope": "flow",
  "match": {
    "proto": "TCP",
    "bytes_gt": 10485760,
    "app_in": ["TLS", "HTTP"]
  }
}
```

Voice in the clear on a regulated network:

```json
{
  "id": "voip-cleartext-g711",
  "name": "Unencrypted G.711 voice stream",
  "severity": 2,
  "scope": "flow",
  "match": { "proto": "UDP", "tag_any": ["voice-g711"] }
}
```

## Loading rules

```bash
voxhound analyze capture.pcap --rules ./my-rules/          # directory of *.json
voxhound analyze capture.pcap --rules ./rules.json         # single file
voxhound analyze capture.pcap --no-rules                    # built-ins off
voxhound rules --check ./my-rules/                          # validate and list
```

Rules are additive: files load on top of the built-in set. A malformed rule is
skipped with a warning and does not abort the run - but `voxhound rules --check`
reports it, which is what CI should use.

## Style guide

1. One behaviour per rule. A rule that fires for three different reasons
   tells the analyst nothing.
2. Prefer tags over title regex when the dissector already classified the
   behaviour - tags are a stable contract, titles are prose.
3. Do not put policy in `severity`. Severity says how bad the behaviour is;
   whether it matters in *your* estate is a filtering decision downstream.
4. Use `scope: flow` for volume and duration, `event` for one-off signals.

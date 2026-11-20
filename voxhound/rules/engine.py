"""A declarative detection layer with no DSL parser to debug.

Rules are JSON documents with a flat ``match`` object. That is intentionally
less expressive than Suricata's language and much easier to review, diff and
generate from a threat-intel pipeline:

.. code-block:: json

    {
      "id": "tls-1.0-1.1",
      "name": "Obsolete TLS version",
      "severity": 2,
      "scope": "event",
      "match": {
        "kind": "tls",
        "title_regex": "TLS1\\.[01]",
        "not_title_regex": "ClientHello"
      },
      "mitre": "T1040"
    }

Supported conditions (all optional, all ANDed):

``kind``, ``title_contains``, ``title_regex``, ``ip_regex``, ``sni_regex``,
``dns_regex``, ``ja4_regex``, ``port``, ``port_in``, ``proto``, ``app``,
``tag_any``, ``app_in``, ``bytes_gt``, ``duration_gt``, ``severity_gte``,
``detail`` (mapping of key → substring), ``note_true`` (mapping of key → bool).
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.model import Alert, AppEvent, Severity

log = logging.getLogger(__name__)

BUILTIN_PATH = Path(__file__).with_name("builtin.json")


@dataclass(slots=True)
class Rule:
    id: str
    name: str
    severity: int = int(Severity.MEDIUM)
    description: str = ""
    scope: str = "event"
    match: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    mitre: str = ""
    enabled: bool = True
    hit_count: int = 0
    _cache: dict[str, re.Pattern[str]] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------ helpers
    def _regex(self, key: str, value: str) -> re.Pattern[str] | None:
        pattern = self._cache.get(key)
        if pattern is None:
            try:
                pattern = re.compile(value, re.IGNORECASE)
            except re.error:
                log.warning("rule %s has an invalid regex for %s: %r", self.id, key, value)
                return None
            self._cache[key] = pattern
        return pattern

    def _regex_ok(self, key: str, haystack: str) -> bool:
        value = self.match.get(key)
        if not value:
            return True
        pattern = self._regex(key, str(value))
        return bool(pattern and pattern.search(haystack or ""))

    def _not_regex_ok(self, key: str, haystack: str) -> bool:
        value = self.match.get(f"not_{key}")
        if not value:
            return True
        pattern = self._regex(f"not_{key}", str(value))
        return not (pattern and pattern.search(haystack or ""))

    # ------------------------------------------------------------------ matching
    def matches_event(self, event: AppEvent, flow: Any | None) -> bool:
        if self.scope != "event" or not self.enabled:
            return False
        m = self.match
        kinds = m.get("kind")
        if kinds:
            wanted = {kinds} if isinstance(kinds, str) else set(kinds)
            if event.kind not in wanted:
                return False
        if not self._regex_ok("title_regex", event.title):
            return False
        if not self._not_regex_ok("title_regex", event.title):
            return False
        contains = m.get("title_contains")
        if contains and str(contains).lower() not in event.title.lower():
            return False
        if m.get("severity_gte") is not None and int(event.severity) < int(m["severity_gte"]):
            return False
        for key, expected in (m.get("detail") or {}).items():
            actual = event.detail.get(key)
            if actual is None or str(expected).lower() not in str(actual).lower():
                return False
        if flow is not None:
            if not self._regex_ok("sni_regex", flow.sni):
                return False
            if not self._regex_ok("ja4_regex", flow.ja4):
                return False
            if not self._regex_ok("ip_regex", f"{flow.src} {flow.dst}"):
                return False
            if not self._regex_ok("dns_regex", " ".join(flow.dns_names)):
                return False
            if m.get("port") is not None and int(m["port"]) not in (flow.sport, flow.dport):
                return False
            ports = m.get("port_in")
            if ports and not ({flow.sport, flow.dport} & {int(p) for p in ports}):
                return False
            if m.get("proto") and str(m["proto"]).upper() != flow.proto_name.upper():
                return False
            apps = m.get("app_in")
            if apps and flow.app not in apps:
                return False
            tags = m.get("tag_any")
            if tags and not (set(tags) & set(flow.tags)):
                return False
        return True

    def matches_flow(self, flow: Any) -> bool:
        if self.scope != "flow" or not self.enabled:
            return False
        m = self.match
        if m.get("bytes_gt") is not None and flow.payload_bytes <= int(m["bytes_gt"]):
            return False
        if m.get("duration_gt") is not None and flow.duration <= float(m["duration_gt"]):
            return False
        ports = m.get("port_in")
        if ports and not ({flow.sport, flow.dport} & {int(p) for p in ports}):
            return False
        if m.get("port") is not None and int(m["port"]) not in (flow.sport, flow.dport):
            return False
        if m.get("proto") and str(m["proto"]).upper() != flow.proto_name.upper():
            return False
        apps = m.get("app_in")
        if apps and flow.app not in apps:
            return False
        if not self._regex_ok("sni_regex", flow.sni):
            return False
        if not self._regex_ok("ja4_regex", flow.ja4):
            return False
        if not self._regex_ok("ip_regex", f"{flow.src} {flow.dst}"):
            return False
        if not self._regex_ok("dns_regex", " ".join(flow.dns_names)):
            return False
        tags = m.get("tag_any")
        if tags and not (set(tags) & set(flow.tags)):
            return False
        notes = m.get("note_true") or {}
        return all(bool(flow.notes.get(key)) == bool(expected) for key, expected in notes.items())


class RuleEngine:
    """Loads rules, evaluates events and flows, keeps hit counters."""

    def __init__(self, rules: Iterable[Rule] = ()) -> None:
        self.rules: list[Rule] = list(rules)
        self.hits = 0
        #: Rules that failed to parse in the last load — surfaced by the CLI so a
        #: typo does not turn into a detector that silently never fires.
        self.skipped: list[str] = []

    # ------------------------------------------------------------------ loading
    @classmethod
    def load_builtin(cls) -> RuleEngine:
        engine = cls()
        if BUILTIN_PATH.exists():
            engine.add_from_file(BUILTIN_PATH)
        return engine

    def add_from_file(self, path: str | Path) -> int:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict) and "rules" in data:
            items = data["rules"]
        elif isinstance(data, dict) and "id" in data:
            # A single bare rule — the most natural thing to hand-write, and
            # previously iterated as a dict, yielding its *keys* and loading
            # nothing at all. Accepting it is strictly better than silence.
            items = [data]
        else:
            raise ValueError(f"{path}: expected a rule, a rule array, or a 'rules' array")
        if not isinstance(items, list):
            raise ValueError(f"{path}: 'rules' must be an array")
        added = 0
        for item in items:
            try:
                self.rules.append(
                    Rule(
                        id=str(item["id"]),
                        name=str(item.get("name", item["id"])),
                        severity=int(item.get("severity", int(Severity.MEDIUM))),
                        description=str(item.get("description", "")),
                        scope=str(item.get("scope", "event")),
                        match=dict(item.get("match", {})),
                        tags=list(item.get("tags", [])),
                        mitre=str(item.get("mitre", "")),
                        enabled=bool(item.get("enabled", True)),
                    )
                )
                added += 1
            except (KeyError, TypeError, ValueError) as exc:
                self.skipped.append(f"{Path(path).name}: {exc}")
                log.warning("skipping malformed rule in %s: %s", path, exc)
        return added

    def add_from_dir(self, path: str | Path) -> int:
        added = 0
        for file in sorted(Path(path).glob("*.json")):
            added += self.add_from_file(file)
        return added

    # ------------------------------------------------------------------ evaluation
    def evaluate_event(self, event: AppEvent, flow: Any | None = None) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            if rule.scope != "event":
                continue
            if rule.matches_event(event, flow):
                rule.hit_count += 1
                self.hits += 1
                alerts.append(
                    Alert(
                        ts=event.ts,
                        rule_id=rule.id,
                        title=rule.name,
                        severity=max(rule.severity, int(event.severity)),
                        description=rule.description,
                        flow_key=event.flow_key,
                        evidence={
                            "event": event.title,
                            **{k: str(v) for k, v in list(event.detail.items())[:6]},
                        },
                    )
                )
        return alerts

    def evaluate_flow(self, flow: Any) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            if rule.scope != "flow":
                continue
            if rule.matches_flow(flow):
                rule.hit_count += 1
                self.hits += 1
                alerts.append(
                    Alert(
                        ts=flow.last_ts,
                        rule_id=rule.id,
                        title=rule.name,
                        severity=rule.severity,
                        description=rule.description,
                        flow_key=flow.key,
                        evidence={
                            "endpoints": flow.endpoints(),
                            "bytes": flow.payload_bytes,
                            "duration": round(flow.duration, 2),
                            "app": flow.app,
                        },
                    )
                )
        return alerts

    # ------------------------------------------------------------------ introspection
    def as_rows(self) -> list[dict[str, Any]]:
        return [
            {
                "id": rule.id,
                "name": rule.name,
                "severity": Severity(rule.severity).label,
                "scope": rule.scope,
                "enabled": rule.enabled,
                "hits": rule.hit_count,
                "mitre": rule.mitre,
                "description": rule.description,
                "match": json.dumps(rule.match, ensure_ascii=False),
            }
            for rule in self.rules
        ]

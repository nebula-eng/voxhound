"""A BPF-expression subset that compiles to a Python predicate.

Two reasons this exists instead of "just call libpcap":

1. **Offline files.** ``tcpdump -w`` captures are analysed on machines without
   Npcap; filtering must still work.
2. **Post-decode predicates.** Analysts filter on decoded fields (``port 5060``)
   and expect it to apply to *flows* and *packets* alike, which a kernel filter
   cannot do for a file.

The grammar is deliberately a strict subset of libpcap's so that the very same
string can be handed to :meth:`voxhound.capture.npcap.LiveHandle.set_filter`
for kernel-side filtering. Supported::

    tcp | udp | icmp | icmp6 | arp | ip | ip6 | vlan [id]
    [src|dst] host 10.0.0.1
    [src|dst] net 10.0.0.0/8
    [src|dst] port 443        portrange 8000-8100
    len > 1000                contains "SILK"
    not X | X and Y | X or Y | ( X )

Anything outside the grammar is rejected with a caret pointing at the problem,
rather than silently passing everything through — a filter that fails open is a
forensics incident of its own.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from ..core.model import IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, Packet

_TOKEN_RE = re.compile(
    r"""
    \s*(?:
      (?P<lparen>\() | (?P<rparen>\)) |
      (?P<op>>=|<=|!=|>|<|=) |
      (?P<str>"[^"]*"|'[^']*') |
      (?P<num>\d+(?:\.\d+)*) |
      (?P<word>[A-Za-z_][A-Za-z0-9_.\-]*) |
      (?P<slash>/) | (?P<dash>-)
    )""",
    re.VERBOSE,
)


class FilterSyntaxError(ValueError):
    def __init__(self, message: str, expression: str, pos: int) -> None:
        super().__init__(f"{message} at offset {pos}: {expression}\n{' ' * pos}^")
        self.expression = expression
        self.pos = pos


@dataclass(slots=True)
class Token:
    kind: str
    value: str
    pos: int


def _tokenize(expr: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m or m.end() == pos:
            if expr[pos:].strip() == "":
                break
            raise FilterSyntaxError(f"unexpected character {expr[pos]!r}", expr, pos)
        pos = m.end()
        kind = m.lastgroup or ""
        tokens.append(Token(kind, m.group(kind), m.start()))
    return tokens


Predicate = Callable[[Packet], bool]


class Filter:
    """Compiled filter: call it with a decoded packet."""

    __slots__ = ("expression", "_fn")

    def __init__(self, expression: str, fn: Predicate) -> None:
        self.expression = expression
        self._fn = fn

    def __call__(self, pkt: Packet) -> bool:
        return self._fn(pkt)

    def matches(self, pkt: Packet) -> bool:
        return self._fn(pkt)

    def __repr__(self) -> str:
        return f"Filter({self.expression!r})"


class _Parser:
    def __init__(self, expr: str) -> None:
        self.expr = expr
        self.tokens = _tokenize(expr)
        self.i = 0

    # ------------------------------------------------------------------ helpers
    def peek(self) -> Token | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self) -> Token:
        tok = self.peek()
        if tok is None:
            raise FilterSyntaxError("unexpected end of filter", self.expr, len(self.expr))
        self.i += 1
        return tok

    def accept_word(self, *words: str) -> Token | None:
        tok = self.peek()
        if tok and tok.kind == "word" and tok.value.lower() in words:
            self.i += 1
            return tok
        return None

    def expect_word(self, *words: str) -> Token:
        tok = self.accept_word(*words)
        if tok is None:
            here = self.peek()
            pos = here.pos if here else len(self.expr)
            raise FilterSyntaxError(f"expected one of {'/'.join(words)}", self.expr, pos)
        return tok

    # ------------------------------------------------------------------ grammar
    def parse(self) -> Predicate:
        if not self.tokens:
            return lambda _pkt: True
        fn = self.parse_or()
        if self.peek() is not None:
            tok = self.peek()
            raise FilterSyntaxError(f"trailing input {tok.value!r}", self.expr, tok.pos)
        return fn

    def parse_or(self) -> Predicate:
        left = self.parse_and()
        while self.accept_word("or", "||"):
            right = self.parse_and()
            left = (lambda a, b: lambda p: a(p) or b(p))(left, right)
        return left

    def parse_and(self) -> Predicate:
        """Also handle BPF's implicit AND: ``tcp port 443`` == ``tcp and port 443``."""
        left = self.parse_not()
        while True:
            if self.accept_word("and", "&&"):
                right = self.parse_not()
                left = (lambda a, b: lambda p: a(p) and b(p))(left, right)
                continue
            if self._starts_primary(self.peek()):
                right = self.parse_not()
                left = (lambda a, b: lambda p: a(p) and b(p))(left, right)
                continue
            return left

    @staticmethod
    def _starts_primary(tok: Token | None) -> bool:
        if tok is None:
            return False
        if tok.kind in ("lparen", "word"):
            return tok.kind == "lparen" or tok.value.lower() not in ("and", "or", "&&", "||")
        return False

    def parse_not(self) -> Predicate:
        if self.accept_word("not", "!"):
            inner = self.parse_not()
            return lambda p: not inner(p)
        return self.parse_primary()

    def parse_primary(self) -> Predicate:
        tok = self.peek()
        if tok is None:
            raise FilterSyntaxError("unexpected end of filter", self.expr, len(self.expr))
        if tok.kind == "lparen":
            self.take()
            inner = self.parse_or()
            closing = self.take()
            if closing.kind != "rparen":
                raise FilterSyntaxError("expected ')'", self.expr, closing.pos)
            return inner
        if tok.kind != "word":
            raise FilterSyntaxError(f"unexpected token {tok.value!r}", self.expr, tok.pos)

        word = tok.value.lower()
        self.take()

        if word in ("tcp", "udp", "icmp", "icmp6", "arp", "ip", "ip6"):
            return self._proto(word)
        if word in ("host", "net", "port", "portrange"):
            return self._directed(word, "any")
        if word in ("src", "dst"):
            direction = word
            nxt = self.take()
            if nxt.kind != "word" or nxt.value.lower() not in ("host", "net", "port", "portrange"):
                raise FilterSyntaxError("expected host/net/port after src/dst", self.expr, nxt.pos)
            return self._directed(nxt.value.lower(), direction)
        if word == "vlan":
            ident = self.peek()
            if ident and ident.kind == "num":
                self.take()
                wanted = int(ident.value)
                return lambda p: wanted in p.vlan
            return lambda p: bool(p.vlan)
        if word in ("len", "length"):
            return self._length()
        if word == "contains":
            raw = self.take()
            if raw.kind != "str":
                raise FilterSyntaxError("contains needs a quoted string", self.expr, raw.pos)
            needle = raw.value[1:-1].encode("utf-8", "replace")
            return lambda p: needle in bytes(p.payload)
        raise FilterSyntaxError(f"unknown primitive {word!r}", self.expr, tok.pos)

    # ------------------------------------------------------------------ primitives
    def _proto(self, word: str) -> Predicate:
        if word == "tcp":
            return lambda p: p.proto == IPPROTO_TCP
        if word == "udp":
            return lambda p: p.proto == IPPROTO_UDP
        if word == "icmp":
            return lambda p: p.proto == IPPROTO_ICMP
        if word == "icmp6":
            return lambda p: p.proto == IPPROTO_ICMPV6
        if word == "arp":
            return lambda p: p.ip_version == 0 and p.proto_name == "ARP"
        if word == "ip":
            return lambda p: p.ip_version == 4
        return lambda p: p.ip_version == 6

    def _directed(self, kind: str, direction: str) -> Predicate:
        tok = self.take()
        if tok.kind in ("num", "word"):
            # Dotted quads arrive as a single ``num`` token because the pattern
            # allows dots; hostnames arrive as ``word``.
            value = tok.value
        else:
            raise FilterSyntaxError(f"expected value for {kind}", self.expr, tok.pos)

        if kind == "portrange":
            low = int(tok.value) if tok.kind == "num" else -1
            if low < 0:
                raise FilterSyntaxError("expected low port", self.expr, tok.pos)
            dash = self.peek()
            if dash is None or dash.kind != "dash":
                raise FilterSyntaxError("expected '-' in portrange", self.expr, dash.pos if dash else tok.pos)
            self.take()
            hi_tok = self.take()
            if hi_tok.kind != "num":
                raise FilterSyntaxError("expected high port", self.expr, hi_tok.pos)
            return _port_pred(low, int(hi_tok.value), direction)

        if kind == "port":
            try:
                port = int(tok.value)
            except ValueError as exc:
                raise FilterSyntaxError("port must be numeric", self.expr, tok.pos) from exc
            return _port_pred(port, port, direction)

        if kind == "host":
            return _host_pred(value, direction)

        # net
        prefix = None
        slash = self.peek()
        if slash and slash.kind == "slash":
            self.take()
            bits = self.take()
            if bits.kind != "num":
                raise FilterSyntaxError("expected prefix length", self.expr, bits.pos)
            prefix = int(bits.value)
        return _net_pred(value, prefix, direction)

    def _length(self) -> Predicate:
        op = self.take()
        if op.kind != "op":
            raise FilterSyntaxError("expected comparison operator", self.expr, op.pos)
        val = self.take()
        if val.kind != "num":
            raise FilterSyntaxError("expected number", self.expr, val.pos)
        limit = int(float(val.value))
        return _cmp_pred("payload_len", op.value, limit)


def _cmp_pred(field: str, op: str, limit: int) -> Predicate:
    if op == ">":
        return lambda p: getattr(p, field) > limit
    if op == ">=":
        return lambda p: getattr(p, field) >= limit
    if op == "<":
        return lambda p: getattr(p, field) < limit
    if op == "<=":
        return lambda p: getattr(p, field) <= limit
    if op == "!=":
        return lambda p: getattr(p, field) != limit
    return lambda p: getattr(p, field) == limit


def _port_pred(low: int, high: int, direction: str) -> Predicate:
    if direction == "src":
        return lambda p: low <= p.sport <= high
    if direction == "dst":
        return lambda p: low <= p.dport <= high
    return lambda p: low <= p.sport <= high or low <= p.dport <= high


def _host_pred(value: str, direction: str) -> Predicate:
    if direction == "src":
        return lambda p: p.src == value
    if direction == "dst":
        return lambda p: p.dst == value
    return lambda p: value in (p.src, p.dst)


def _net_pred(value: str, prefix: int | None, direction: str) -> Predicate:
    from ipaddress import ip_network

    try:
        network = ip_network(value if prefix is None else f"{value}/{prefix}", strict=False)
    except ValueError as exc:
        raise FilterSyntaxError(f"bad network {value!r}", value, 0) from exc

    def _in(pkt: Packet) -> bool:
        for addr in (pkt.src, pkt.dst):
            try:
                from ipaddress import ip_address

                if ip_address(addr) in network:
                    return True
            except ValueError:
                continue
        return False

    if direction == "src":
        return lambda p: _safe_in(p.src, network)
    if direction == "dst":
        return lambda p: _safe_in(p.dst, network)
    return _in


def _safe_in(addr: str, network: object) -> bool:
    from ipaddress import ip_address

    try:
        return ip_address(addr) in network  # type: ignore[operator]
    except ValueError:
        return False


def compile_filter(expression: str | None) -> Filter:
    """Compile a filter expression; empty/None means "match everything"."""
    if not expression or not expression.strip():
        return Filter("", lambda _pkt: True)
    parser = _Parser(expression.strip())
    return Filter(expression.strip(), parser.parse())

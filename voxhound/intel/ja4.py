"""TLS / TCP fingerprinting: JA4, JA4S, JA3, JA4T and p0f-style OS hints.

Implemented from the FoxIO specifications. The point of doing the arithmetic
ourselves — rather than shelling out to a fingerprinting service — is that
fingerprints must be computable on an air-gapped capture, offline, with no
network egress.

Reference notes that matter for correctness:

* GREASE values (RFC 8701) are excluded *everywhere*, including the counts.
* The TLS version in ``JA4_a`` comes from ``supported_versions`` when present,
  never from the legacy handshake version.
* ``JA4_b`` hashes ciphers sorted as 4-digit lowercase hex, comma-joined.
* ``JA4_c`` hashes extensions sorted the same way with SNI and ALPN removed,
  then ``_``, then signature algorithms **in wire order**. The extension *count*
  in ``JA4_a`` still includes SNI and ALPN.
* An empty list hashes to the literal ``000000000000``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

GREASE_VALUES = frozenset(
    {
        0x0A0A,
        0x1A1A,
        0x2A2A,
        0x3A3A,
        0x4A4A,
        0x5A5A,
        0x6A6A,
        0x7A7A,
        0x8A8A,
        0x9A9A,
        0xAAAA,
        0xBABA,
        0xCACA,
        0xDADA,
        0xEAEA,
        0xFAFA,
    }
)

EMPTY_HASH = "000000000000"


def is_grease(value: int) -> bool:
    """RFC 8701: ``0x?A?A`` with equal bytes and low nibble ``A``."""
    return value in GREASE_VALUES or ((value >> 8) == (value & 0xFF) and (value & 0x0F) == 0x0A)


def version_code(versions: Sequence[int], legacy: int) -> str:
    """Highest offered version → two-char code used in JA4."""
    best = max(versions) if versions else legacy
    mapping = {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
        0xFEFF: "d1",
        0xFEFD: "d2",
        0xFEFC: "d3",
    }
    return mapping.get(best, "00")


def alpn_code(alpn: Sequence[str]) -> str:
    """First and last *alphanumeric* character of the first ALPN value."""
    if not alpn:
        return "00"
    first = alpn[0]
    cleaned = "".join(ch for ch in first if ch.isalnum())
    if len(cleaned) < 1:
        return "00"
    return (cleaned[0] + cleaned[-1]).lower()


def _hex_list(values: Iterable[int]) -> str:
    return ",".join(f"{v:04x}" for v in values)


def _truncated_sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def compute_ja4(
    *,
    ciphers: Sequence[int],
    extensions: Sequence[int],
    sig_algs: Sequence[int],
    versions: Sequence[int],
    legacy_version: int,
    alpn: Sequence[str],
    sni: str | None,
    protocol: str = "t",
) -> str:
    """Full ``JA4_a_JA4_b_JA4_c`` string."""
    ciphers_clean = [c for c in ciphers if not is_grease(c)]
    exts_clean = [e for e in extensions if not is_grease(e)]
    sigs_clean = [s for s in sig_algs if not is_grease(s)]

    part_a = "".join(
        (
            protocol,
            version_code(versions, legacy_version),
            "d" if sni else "i",
            f"{min(len(ciphers_clean), 99):02d}",
            f"{min(len(exts_clean), 99):02d}",
            alpn_code(alpn),
        )
    )
    part_b = _truncated_sha256(_hex_list(sorted(ciphers_clean))) if ciphers_clean else EMPTY_HASH
    hash_exts = sorted(e for e in exts_clean if e not in (0x0000, 0x0010))
    base = _hex_list(hash_exts)
    if sigs_clean:
        base += "_" + _hex_list(sigs_clean)
    part_c = _truncated_sha256(base) if base else EMPTY_HASH
    return f"{part_a}_{part_b}_{part_c}"


def compute_ja4s(
    *,
    cipher: int,
    extensions: Sequence[int],
    alpn: Sequence[str],
    version: int,
    protocol: str = "t",
) -> str:
    """Server-side counterpart: chosen cipher rather than offered ciphers."""
    exts_clean = [e for e in extensions if not is_grease(e)]
    part_a = "".join(
        (
            protocol,
            version_code([version], version),
            f"{min(len(exts_clean), 99):02d}",
            alpn_code(alpn),
        )
    )
    part_c = _truncated_sha256(_hex_list(sorted(e for e in exts_clean if e not in (0x0000, 0x0010))))
    return f"{part_a}_{cipher:04x}_{part_c}"


def compute_ja3(
    *,
    ciphers: Sequence[int],
    extensions: Sequence[int],
    curves: Sequence[int] = (),
    point_formats: Sequence[int] = (),
    legacy_version: int = 0x0303,
) -> str:
    """Legacy MD5 fingerprint, kept because many blocklists still key on it."""
    payload = ",".join(
        (
            str(legacy_version),
            "-".join(str(c) for c in ciphers if not is_grease(c)),
            "-".join(str(e) for e in extensions if not is_grease(e)),
            "-".join(str(c) for c in curves),
            "-".join(str(f) for f in point_formats),
        )
    )
    return hashlib.md5(payload.encode(), usedforsecurity=False).hexdigest()


def compute_ja4t(*, window: int, options: Sequence[int], mss: int, window_scale: int) -> str:
    """TCP-level fingerprint: ``window_options_mss_wscale``."""
    opt_hex = "".join(f"{o:02x}" for o in options)
    return f"{window}_{opt_hex or '00'}_{mss or 0}_{window_scale if window_scale >= 0 else 0}"


QUIC_VERSION_NAMES = {
    0x00000001: "QUIC v1",
    0x6B3343CF: "QUIC v2",
    0xFF00001D: "draft-29",
    0xFF00001C: "draft-28",
    0x51303530: "QUIC v1 (grease alt)",
}


def quic_version_name(version: int) -> str:
    return QUIC_VERSION_NAMES.get(version, f"0x{version:08x}")

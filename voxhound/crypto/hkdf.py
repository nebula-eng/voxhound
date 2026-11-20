"""HKDF and the TLS 1.3 / QUIC "expand label" construction (RFC 5869, 8446 §7.1).

QUIC's Initial secrets are HKDF-SHA256 outputs over the connection ID, labelled
``"client in"`` / ``"server in"``. Getting this exactly right is what separates
"we detect QUIC" from "we read QUIC's ClientHello".
"""

from __future__ import annotations

import hashlib
import hmac

HASH = hashlib.sha256
HASH_LEN = 32


def hkdf_extract(salt: bytes, ikm: bytes, *, hash_fn: object = HASH) -> bytes:
    return hmac.new(salt or b"\x00" * HASH_LEN, ikm, hash_fn).digest()  # type: ignore[arg-type]


def hkdf_expand(prk: bytes, info: bytes, length: int, *, hash_fn: object = HASH) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hash_fn).digest()  # type: ignore[arg-type]
        out += block
        counter += 1
    return out[:length]


def hkdf_expand_label(secret: bytes, label: str, context: bytes = b"", length: int = 32) -> bytes:
    """``HKDF-Expand-Label``: length-prefixed "tls13 " + label + context."""
    full_label = b"tls13 " + label.encode()
    info = length.to_bytes(2, "big") + bytes([len(full_label)]) + full_label + bytes([len(context)]) + context
    return hkdf_expand(secret, info, length)


QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
QUIC_V2_SALT = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")


def quic_initial_secrets(dcid: bytes, *, version: int = 0x00000001) -> dict[str, bytes]:
    """Derive client/server initial key, iv and header-protection key.

    Only the version-1 and version-2 salts are standardised; unknown versions
    return an empty mapping so callers degrade instead of guessing.
    """
    salt = {0x00000001: QUIC_V1_SALT, 0x6B3343CF: QUIC_V2_SALT}.get(version)
    if salt is None:
        return {}
    initial_secret = hkdf_extract(salt, dcid)
    client = hkdf_expand_label(initial_secret, "client in", b"", 32)
    server = hkdf_expand_label(initial_secret, "server in", b"", 32)
    return {
        "client_key": hkdf_expand_label(client, "quic key", b"", 16),
        "client_iv": hkdf_expand_label(client, "quic iv", b"", 12),
        "client_hp": hkdf_expand_label(client, "quic hp", b"", 16),
        "server_key": hkdf_expand_label(server, "quic key", b"", 16),
        "server_iv": hkdf_expand_label(server, "quic iv", b"", 12),
        "server_hp": hkdf_expand_label(server, "quic hp", b"", 16),
    }

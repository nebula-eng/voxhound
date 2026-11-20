"""AES (128/192/256) and GCM in pure Python.

Why a hand-rolled cipher in a network tool? Because QUIC's Initial packets are
encrypted with AES-128-GCM using keys derived from the connection ID alone
(RFC 9001 §5.2). Decrypting them is how you recover SNI from a QUIC handshake —
and that requires AES. The standard library has no block cipher, and adding a
C dependency would break the "engine imports nothing" rule.

Correctness is anchored to published vectors (FIPS-197 appendix C, NIST GCM test
cases) in ``tests/test_crypto.py``. Performance is irrelevant here: a handful of
packets per connection, never bulk data.

The S-box is *computed* from the GF(2^8) definition rather than typed in, which
removes the single most common transcription bug in home-grown AES code.
"""

from __future__ import annotations


# --------------------------------------------------------------------------- GF(2^8)
def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _gmul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        b >>= 1
        a = _xtime(a)
    return result


def _build_sbox() -> tuple[list[int], list[int]]:
    sbox = [0] * 256
    inv_sbox = [0] * 256
    for value in range(256):
        # multiplicative inverse in GF(2^8); 0 maps to 0 by definition
        inverse = 0
        if value:
            for candidate in range(1, 256):
                if _gmul(value, candidate) == 1:
                    inverse = candidate
                    break
        s = inverse
        s ^= ((inverse << 1) | (inverse >> 7)) & 0xFF
        s ^= ((inverse << 2) | (inverse >> 6)) & 0xFF
        s ^= ((inverse << 3) | (inverse >> 5)) & 0xFF
        s ^= ((inverse << 4) | (inverse >> 4)) & 0xFF
        s ^= 0x63
        sbox[value] = s
        inv_sbox[s] = value
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sbox()
RCON = [0x01]
for _ in range(13):
    RCON.append(_xtime(RCON[-1]))


class AES:
    """Block cipher in ECB mode — GCM/CTR drive it, nobody calls it directly."""

    __slots__ = ("_round_keys", "rounds")

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self.rounds = {16: 10, 24: 12, 32: 14}[len(key)]
        self._round_keys = self._expand(key)

    # ------------------------------------------------------------------ key schedule
    def _expand(self, key: bytes) -> list[list[int]]:
        nk = len(key) // 4
        words = [list(key[4 * i : 4 * i + 4]) for i in range(nk)]
        total = 4 * (self.rounds + 1)
        for i in range(nk, total):
            temp = list(words[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [SBOX[b] for b in temp]
                temp[0] ^= RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                temp = [SBOX[b] for b in temp]
            words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
        return [sum(words[4 * r : 4 * r + 4], []) for r in range(self.rounds + 1)]

    # ------------------------------------------------------------------ round transform
    @staticmethod
    def _add_round_key(state: list[int], key: list[int]) -> None:
        for i in range(16):
            state[i] ^= key[i]

    @staticmethod
    def _sub_bytes(state: list[int]) -> None:
        for i in range(16):
            state[i] = SBOX[state[i]]

    @staticmethod
    def _shift_rows(state: list[int]) -> None:
        # state is column-major: index = row + 4*column
        for row in range(1, 4):
            values = [state[row + 4 * c] for c in range(4)]
            values = values[row:] + values[:row]
            for c in range(4):
                state[row + 4 * c] = values[c]

    @staticmethod
    def _mix_columns(state: list[int]) -> None:
        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
            state[i] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
            state[i + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
            state[i + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
            state[i + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("AES block must be 16 bytes")
        state = list(block)
        self._add_round_key(state, self._round_keys[0])
        for round_index in range(1, self.rounds):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self._round_keys[round_index])
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self._round_keys[self.rounds])
        return bytes(state)


# --------------------------------------------------------------------------- GHASH / GCM
def _gf128_mul(x: int, y: int) -> int:
    """Carry-less multiplication modulo x^128 + x^7 + x^2 + x + 1."""
    result = 0
    v = y
    for bit in range(127, -1, -1):
        if (x >> bit) & 1:
            result ^= v
        if v & 1:
            v = (v >> 1) ^ 0xE1000000000000000000000000000000
        else:
            v >>= 1
    return result


def _ghash(h: int, data: bytes) -> int:
    state = 0
    for offset in range(0, len(data), 16):
        block = data[offset : offset + 16]
        if len(block) < 16:
            block = block + b"\x00" * (16 - len(block))
        state = _gf128_mul(state ^ int.from_bytes(block, "big"), h)
    return state


def _pad16(data: bytes) -> bytes:
    return data + b"\x00" * ((16 - len(data) % 16) % 16)


def _gctr(aes: AES, initial_counter: int, data: bytes) -> bytes:
    out = bytearray()
    counter = initial_counter
    for offset in range(0, len(data), 16):
        block = data[offset : offset + 16]
        keystream = aes.encrypt_block(counter.to_bytes(16, "big"))
        out += bytes(a ^ b for a, b in zip(block, keystream))
        counter = (counter & ~0xFFFFFFFF) | ((counter + 1) & 0xFFFFFFFF)
    return bytes(out)


def gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Return ``(ciphertext, tag)`` for a 96-bit nonce — the only size QUIC uses."""
    if len(nonce) != 12:
        raise ValueError("GCM here supports 12-byte nonces only")
    aes = AES(key)
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    j0 = int.from_bytes(nonce + b"\x00\x00\x00\x01", "big")
    ciphertext = _gctr(aes, (j0 & ~0xFFFFFFFF) | ((j0 + 1) & 0xFFFFFFFF), plaintext)
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(plaintext) * 8).to_bytes(8, "big")
    tag_mask = aes.encrypt_block(j0.to_bytes(16, "big"))
    tag = bytes(
        a ^ b
        for a, b in zip(
            _ghash(h, _pad16(aad) + _pad16(ciphertext) + lengths).to_bytes(16, "big"),
            tag_mask,
        )
    )
    return ciphertext, tag


def gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt and verify; raises :class:`ValueError` on tag mismatch."""
    aes = AES(key)
    h = int.from_bytes(aes.encrypt_block(b"\x00" * 16), "big")
    j0 = int.from_bytes(nonce + b"\x00\x00\x00\x01", "big")
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    tag_mask = aes.encrypt_block(j0.to_bytes(16, "big"))
    expected = bytes(
        a ^ b
        for a, b in zip(
            _ghash(h, _pad16(aad) + _pad16(ciphertext) + lengths).to_bytes(16, "big"),
            tag_mask,
        )
    )
    if expected != tag:
        raise ValueError("GCM tag mismatch")
    return _gctr(aes, (j0 & ~0xFFFFFFFF) | ((j0 + 1) & 0xFFFFFFFF), ciphertext)


class AesCtr:
    """CTR mode with a caller-supplied 16-byte initial counter block."""

    def __init__(self, key: bytes, counter_block: bytes) -> None:
        self._aes = AES(key)
        self._counter = int.from_bytes(counter_block, "big")

    def update(self, data: bytes) -> bytes:
        out = _gctr(self._aes, self._counter, data)
        self._counter = (self._counter + (len(data) + 15) // 16) & ((1 << 128) - 1)
        return out

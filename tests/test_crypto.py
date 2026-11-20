"""Cryptographic primitive tests: AES, GCM, HKDF, QUIC initial keys.

The QUIC Initial decryption in ``app/quic.py`` is only as trustworthy as these
three primitives, so each is anchored to a published vector instead of a
round-trip against itself:

* AES block cipher — FIPS-197 appendix C (128/192/256)
* AES-GCM — NIST GCM specification test cases 1, 2 and 4 (with AAD)
* HKDF — RFC 5869 test case 1
* HKDF-Expand-Label / QUIC initial secrets — RFC 9001 appendix A
"""

from __future__ import annotations

import pytest

from voxhound.crypto.aes import AES, gcm_decrypt, gcm_encrypt
from voxhound.crypto.hkdf import hkdf_expand, hkdf_expand_label, hkdf_extract, quic_initial_secrets

# --------------------------------------------------------------------------- AES
FIPS197 = (
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
)


@pytest.mark.parametrize(("key_hex", "expected"), FIPS197)
def test_aes_block_fips197(key_hex: str, expected: str) -> None:
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert AES(bytes.fromhex(key_hex)).encrypt_block(plaintext).hex() == expected


def test_aes_rejects_wrong_key_size() -> None:
    with pytest.raises(ValueError):
        AES(b"\x00" * 15)


# --------------------------------------------------------------------------- GCM
def test_gcm_empty_plaintext_vector() -> None:
    """NIST GCM test case 1: no plaintext, no AAD — the tag is the whole output."""
    ciphertext, tag = gcm_encrypt(bytes(16), bytes(12), b"")
    assert ciphertext == b""
    assert tag.hex() == "58e2fccefa7e3061367f1d57a4e7455a"


def test_gcm_single_block_vector() -> None:
    """NIST GCM test case 2: one all-zero block."""
    ciphertext, tag = gcm_encrypt(bytes(16), bytes(12), bytes(16))
    assert ciphertext.hex() == "0388dace60b6a392f328c2b971b2fe78"
    assert tag.hex() == "ab6e47d42cec13bdf53a67b21257bddf"


def test_gcm_with_aad_vector() -> None:
    """NIST GCM test case 4: 60-byte plaintext plus 20-byte AAD."""
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    plaintext = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    )
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    ciphertext, tag = gcm_encrypt(key, nonce, plaintext, aad)
    assert ciphertext.hex() == (
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
    )
    assert tag.hex() == "5bc94fbc3221a5db94fae95ae7121a47"
    assert gcm_decrypt(key, nonce, ciphertext, tag, aad) == plaintext


def test_gcm_rejects_tampered_tag_and_aad() -> None:
    key, nonce = bytes(16), bytes(12)
    ciphertext, tag = gcm_encrypt(key, nonce, b"payload", b"header")
    with pytest.raises(ValueError):
        gcm_decrypt(key, nonce, ciphertext, bytes(16), b"header")
    with pytest.raises(ValueError):
        gcm_decrypt(key, nonce, ciphertext, tag, b"different")


def test_gcm_requires_96_bit_nonce() -> None:
    with pytest.raises(ValueError):
        gcm_encrypt(bytes(16), bytes(8), b"x")


# --------------------------------------------------------------------------- HKDF
def test_hkdf_rfc5869_case1() -> None:
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    prk = hkdf_extract(salt, ikm)
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    okm = hkdf_expand(prk, info, 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_hkdf_expand_label_matches_rfc9001_schedule() -> None:
    """RFC 9001 A.1: DCID ``8394c8f03e515708`` derives these exact keys."""
    dcid = bytes.fromhex("8394c8f03e515708")
    secrets = quic_initial_secrets(dcid)
    assert secrets["client_key"].hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert secrets["client_iv"].hex() == "fa044b2f42a3fd3b46fb255c"
    assert secrets["client_hp"].hex() == "9f50449e04a0e810283a1e9933adedd2"
    assert secrets["server_key"].hex() == "cf3a5331653c364c88f0f379b6067e37"
    assert secrets["server_iv"].hex() == "0ac1493ca1905853b0bba03e"
    assert secrets["server_hp"].hex() == "c206b8d9b9f0f37644430b490eeaa314"


def test_quic_v2_salt_differs_from_v1() -> None:
    dcid = bytes.fromhex("8394c8f03e515708")
    v1 = quic_initial_secrets(dcid, version=0x00000001)
    v2 = quic_initial_secrets(dcid, version=0x6B3343CF)
    assert v1["client_key"] != v2["client_key"]


def test_hkdf_expand_label_prefixes_tls13() -> None:
    secret = bytes(range(32))
    plain = hkdf_expand(secret, b"tls13 key", 16)
    labelled = hkdf_expand_label(secret, "key", b"", 16)
    assert len(plain) == len(labelled) == 16
    assert plain != labelled  # the label header must actually participate

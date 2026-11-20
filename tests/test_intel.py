"""Fingerprinting and certificate tests.

The JA4 vector is the one published in the FoxIO specification: Chrome's cipher
list must hash to ``8daaf6152771``. If this test ever fails, every fingerprint
the tool emits is suspect.
"""

from __future__ import annotations

import datetime as dt

from voxhound.intel import ja4
from voxhound.intel.p0f import guess_os
from voxhound.intel.x509 import parse_certificate
from voxhound.simulate import _fake_certificate

CHROME_CIPHERS = [
    0x1301,
    0x1302,
    0x1303,
    0xC02B,
    0xC02F,
    0xC02C,
    0xC030,
    0xCCA9,
    0xCCA8,
    0xC013,
    0xC014,
    0x009C,
    0x009D,
    0x002F,
    0x0035,
]


def test_grease_detection_matches_rfc_8701() -> None:
    assert ja4.is_grease(0x0A0A)
    assert ja4.is_grease(0xFAFA)
    assert not ja4.is_grease(0x1301)
    assert not ja4.is_grease(0x000A)


def test_ja4_cipher_hash_matches_published_vector() -> None:
    fingerprint = ja4.compute_ja4(
        ciphers=CHROME_CIPHERS,
        extensions=[0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x000D, 0x002B, 0x002D, 0x0033],
        sig_algs=[0x0403, 0x0804, 0x0401, 0x0503],
        versions=[0x0304, 0x0303],
        legacy_version=0x0303,
        alpn=["h2", "http/1.1"],
        sni="example.com",
    )
    part_a, part_b, part_c = fingerprint.split("_")
    assert part_a == "t13d1511h2"  # 15 ciphers, 11 extensions, ALPN h2
    assert part_b == "8daaf6152771"  # FoxIO's published Chrome cipher hash
    assert len(part_c) == 12


def test_ja4_ignores_grease_and_extension_order() -> None:
    def compute(extensions: list[int]) -> str:
        return ja4.compute_ja4(
            ciphers=[0x0A0A, 0x1301, 0x1302],
            extensions=extensions,
            sig_algs=[],
            versions=[0x0304],
            legacy_version=0x0303,
            alpn=[],
            sni=None,
        )

    a = compute([0x002B, 0x0033, 0x000A])
    b = compute([0x000A, 0x002B, 0x0033, 0x1A1A])
    assert a.split("_")[2] == b.split("_")[2]
    assert a.split("_")[1] == b.split("_")[1]


def test_ja4_no_sni_uses_i_flag_and_00_alpn() -> None:
    fingerprint = ja4.compute_ja4(
        ciphers=[0x1301],
        extensions=[],
        sig_algs=[],
        versions=[],
        legacy_version=0x0301,
        alpn=[],
        sni=None,
    )
    assert fingerprint.startswith("t10i0100")
    assert fingerprint.endswith("000000000000")


def test_ja4t_layout() -> None:
    value = ja4.compute_ja4t(window=64240, options=[2, 4, 8, 1, 3], mss=1460, window_scale=8)
    assert value == "64240_0204080103_1460_8"


def test_ja3_is_stable_for_same_input() -> None:
    kwargs = {
        "ciphers": [0x1301, 0xC02B],
        "extensions": [0x0000, 0x0010],
        "curves": [0x001D],
        "point_formats": [0],
        "legacy_version": 0x0303,
    }
    assert ja4.compute_ja3(**kwargs) == ja4.compute_ja3(**kwargs)


# --------------------------------------------------------------------------- X.509
def test_certificate_fields_are_extracted() -> None:
    der = _fake_certificate("api.example.com", "Example Root CA", sans=("api.example.com", "*.example.com"))
    info = parse_certificate(der)
    assert info.common_name == "api.example.com"
    assert "Example Root CA" in info.issuer
    assert "*.example.com" in info.sans
    assert info.signature_algorithm == "sha256WithRSA"
    assert not info.self_signed


def test_self_signed_and_expiry_detection() -> None:
    der = _fake_certificate("rogue.local", "rogue.local", sans=("rogue.local",), days=-30, self_signed=True)
    info = parse_certificate(der)
    assert info.self_signed
    assert info.expired(dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc))


def test_hostname_matching_handles_wildcards() -> None:
    der = _fake_certificate("example.com", "CA", sans=("*.example.com",))
    info = parse_certificate(der)
    assert info.matches_host("api.example.com")
    assert not info.matches_host("example.org")
    assert not info.matches_host("deep.api.example.com")


# --------------------------------------------------------------------------- OS hints
def test_os_guess_prefers_option_order() -> None:
    windows = guess_os(ttl=127, mss=1460, wscale=8, opt_sig="MSS,NOP,WS,NOP,NOP,SACK_PERM")
    linux = guess_os(ttl=63, mss=1460, wscale=7, opt_sig="MSS,SACK_PERM,TS,NOP,WS")
    assert "Windows" in windows.name
    assert "Linux" in linux.name
    assert windows.confidence >= 0.8


def test_rule_file_accepts_a_single_bare_object(tmp_path) -> None:
    """A hand-written single rule must load, not vanish.

    Regression: the loader iterated any dict as ``items``, so a bare rule object
    yielded its *keys* and silently contributed zero rules.
    """
    import json

    from voxhound.rules.engine import RuleEngine

    path = tmp_path / "one.json"
    path.write_text(
        json.dumps(
            {
                "id": "my-rule",
                "name": "访问了不想看到的域名",
                "severity": 3,
                "scope": "event",
                "match": {"kind": "dns", "title_regex": r"bad-domain\.com"},
            }
        ),
        encoding="utf-8",
    )
    engine = RuleEngine()
    assert engine.add_from_file(path) == 1
    assert [rule.id for rule in engine.rules] == ["my-rule"]
    assert engine.skipped == []


def test_rule_file_rejects_unknown_shape(tmp_path) -> None:
    """An unrecognised structure must complain instead of loading nothing."""
    import json

    import pytest

    from voxhound.rules.engine import RuleEngine

    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"foo": 1}), encoding="utf-8")
    with pytest.raises(ValueError, match="expected a rule"):
        RuleEngine().add_from_file(path)

    path.write_text(json.dumps({"rules": {"a": 1}}), encoding="utf-8")
    with pytest.raises(ValueError, match="must be an array"):
        RuleEngine().add_from_file(path)


def test_malformed_rule_is_recorded_not_swallowed(tmp_path) -> None:
    import json

    from voxhound.rules.engine import RuleEngine

    path = tmp_path / "partial.json"
    path.write_text(json.dumps({"rules": [{"id": "ok", "match": {}}, {"name": "no id"}]}), encoding="utf-8")
    engine = RuleEngine()
    assert engine.add_from_file(path) == 1
    assert engine.skipped and "no id" not in engine.skipped[0]

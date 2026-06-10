"""Security regression tests for the desktop backend (local/app.py).

Covers the Phase-1 hardening:
  S6 — credential redaction now catches IPSec/SNMPv3 secrets
  S7 — _decrypt_api_key fails closed (never returns ciphertext as a key)
  S1 — _verify_installer rejects a bad hash and an unsigned binary
"""
import hashlib

import pytest

import app  # noqa: E402  (path set up in conftest.py)


# ---------------------------------------------------------------------------
# S6 — redaction coverage
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("xml", [
    "<esp-auth-key>0xDEADBEEF</esp-auth-key>",
    "<ah-auth-key>topsecret</ah-auth-key>",
    "<auth-password>snmpAuthPass</auth-password>",
    "<priv-password>snmpPrivPass</priv-password>",
    "<authpwd>abc123</authpwd>",
    "<privpwd>xyz789</privpwd>",
])
def test_redacts_new_xml_credential_tags(xml):
    out, n = app.sanitize_config_text(xml)
    assert n == 1
    assert "[REDACTED]" in out
    # The secret value itself must be gone.
    for secret in ("DEADBEEF", "topsecret", "snmpAuthPass", "snmpPrivPass", "abc123", "xyz789"):
        assert secret not in out


def test_redacts_new_set_format_keywords():
    cfg = "set network ike gateway GW1 protocol ikev2 esp-auth-key 0xCAFEBABE"
    out, n = app.sanitize_config_text(cfg)
    assert n == 1
    assert "CAFEBABE" not in out
    assert "[REDACTED]" in out


def test_redaction_preserves_structure_and_ips():
    # The product intentionally keeps IPs/topology so the model can diagnose;
    # only credential *values* are stripped.
    cfg = (
        "set network interface ethernet1/1 ip 203.0.113.10/24\n"
        "set network ike gateway GW1 pre-shared-key SuperSecretPSK\n"
    )
    out, n = app.sanitize_config_text(cfg)
    assert "203.0.113.10/24" in out          # structure preserved
    assert "SuperSecretPSK" not in out        # credential stripped
    assert n == 1


# ---------------------------------------------------------------------------
# S7 — decrypt fails closed
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("encrypted,token", [
    ("", "sometoken"),
    ("ciphertext", ""),
    ("ciphertext", None),
    (None, "sometoken"),
])
def test_decrypt_fails_closed_on_missing_inputs(encrypted, token):
    # Must never hand back the ciphertext as if it were a usable plaintext key.
    assert app._decrypt_api_key(encrypted, token) is None


def test_decrypt_returns_none_on_garbage_ciphertext():
    assert app._decrypt_api_key("not-valid-fernet", "a" * 40) is None


# ---------------------------------------------------------------------------
# S1 — installer integrity verification fails closed
# ---------------------------------------------------------------------------
def test_verify_installer_rejects_hash_mismatch(tmp_path):
    f = tmp_path / "fake_setup.exe"
    f.write_bytes(b"malicious payload")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        app._verify_installer(f, expected_sha256="0" * 64)


def test_verify_installer_rejects_unsigned_binary(tmp_path):
    # Hash matches, but the file isn't Authenticode-signed → must still refuse.
    f = tmp_path / "unsigned_setup.exe"
    payload = b"unsigned but hash-correct"
    f.write_bytes(payload)
    good_hash = hashlib.sha256(payload).hexdigest()
    with pytest.raises(ValueError):
        app._verify_installer(f, expected_sha256=good_hash)

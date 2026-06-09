"""Tests for the read-only PAN-OS client and test-command builder."""
import pytest

from panos_api import client as pc
from panos_api import testcmd


# ── host validation ──────────────────────────────────────────────────────
@pytest.mark.parametrize("host", ["192.0.2.1", "fw01", "fw01.corp.example.com", "2001:db8::1"])
def test_valid_host_accepts(host):
    assert pc.valid_host(host)


@pytest.mark.parametrize("host", ["", "https://fw01", "fw01/api", "a b", "10.0.0.1/24"])
def test_valid_host_rejects(host):
    assert not pc.valid_host(host)


def test_client_rejects_bad_host():
    with pytest.raises(ValueError):
        pc.FirewallClient("https://fw01", "KEY")


# ── response parsing ─────────────────────────────────────────────────────
class _Resp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")


def test_parse_raises_on_api_error():
    xml = '<response status="error"><msg><line>Invalid credentials</line></msg></response>'
    with pytest.raises(pc.PanosError, match="Invalid credentials"):
        pc._parse(_Resp(xml))


def test_system_info_parses(monkeypatch):
    info_xml = (
        '<response status="success"><result><system>'
        '<hostname>fw-edge-01</hostname><model>PA-440</model>'
        '<serial>012345678901</serial><sw-version>11.1.4-h7</sw-version>'
        '<family>440</family></system></result></response>'
    )
    monkeypatch.setattr(pc.httpx, "get", lambda *a, **k: _Resp(info_xml))
    fw = pc.FirewallClient("192.0.2.1", "KEY", verify=False)
    info = fw.system_info()
    assert info["sw-version"] == "11.1.4-h7"
    assert info["model"] == "PA-440"
    assert info["hostname"] == "fw-edge-01"


def test_keygen(monkeypatch):
    monkeypatch.setattr(
        pc.httpx, "get",
        lambda *a, **k: _Resp('<response status="success"><result><key>ABC123</key></result></response>'),
    )
    assert pc.generate_api_key("192.0.2.1", "admin", "pw", verify=False) == "ABC123"


# ── test-command builder ─────────────────────────────────────────────────
def test_security_policy_match_builds():
    out = testcmd.security_policy_match(
        source="10.0.0.5", destination="8.8.8.8", protocol="6",
        destination_port=443, application="ssl")
    assert out["cli"] == (
        "test security-policy-match source 10.0.0.5 destination 8.8.8.8 "
        "protocol 6 destination-port 443 application ssl")
    assert "<security-policy-match>" in out["op_xml"]
    assert "<destination-port>443</destination-port>" in out["op_xml"]


def test_routing_fib_lookup_builds():
    out = testcmd.routing_fib_lookup(ip="8.8.8.8", virtual_router="default")
    assert "<fib-lookup>" in out["op_xml"]
    assert "8.8.8.8" in out["cli"]


def test_testcmd_rejects_bad_ip():
    with pytest.raises(ValueError):
        testcmd.security_policy_match(source="not-an-ip", destination="8.8.8.8")


def test_build_dispatch_unknown():
    with pytest.raises(ValueError):
        testcmd.build("bogus", {})

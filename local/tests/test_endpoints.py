"""Endpoint tests for the firewall + checks features (firewall mocked)."""
import pytest
from fastapi.testclient import TestClient

import app
import panos_api


@pytest.fixture
def client(monkeypatch):
    # In-memory settings so tests never touch ~/.pan_copilot.
    store = {}

    def fake_load():
        s = dict(app._DEFAULT_SETTINGS)
        s.update(store)
        return s

    def fake_save(data):
        store.clear()
        store.update(data)

    monkeypatch.setattr(app, "load_settings", fake_load)
    monkeypatch.setattr(app, "save_settings", fake_save)
    return TestClient(app.app), store


class _FakeClient:
    def __init__(self, host, key, verify=True):
        self.host, self.key, self.verify = host, key, verify

    def system_info(self):
        return {"hostname": "fw-edge-01", "model": "PA-440", "sw-version": "11.1.4-h7"}

    def op(self, cmd):
        import xml.etree.ElementTree as ET
        return ET.fromstring('<response status="success"><result>OK</result></response>')


# ── checks ────────────────────────────────────────────────────────────────
def test_checks_run_paste(client):
    c, _ = client
    cfg = (
        'set rulebase security rules "allow-all" from any\n'
        'set rulebase security rules "allow-all" to any\n'
        'set rulebase security rules "allow-all" source any\n'
        'set rulebase security rules "allow-all" destination any\n'
        'set rulebase security rules "allow-all" application any\n'
        'set rulebase security rules "allow-all" action allow\n'
    )
    r = c.post("/api/checks/run", json={"config_text": cfg, "source": "paste"})
    assert r.status_code == 200
    body = r.json()
    assert body["rule_count"] == 1
    assert any(f["category"] == "any-any-rule" for f in body["findings"])


def test_checks_run_empty_rejected(client):
    c, _ = client
    r = c.post("/api/checks/run", json={"config_text": "  ", "source": "paste"})
    assert r.status_code == 400


# ── firewall connect / status / disconnect ─────────────────────────────────
def test_firewall_connect_stores_dpapi_key(client, monkeypatch):
    c, store = client
    monkeypatch.setattr(panos_api, "generate_api_key", lambda *a, **k: "FAKEKEY123")
    monkeypatch.setattr(panos_api, "FirewallClient", _FakeClient)

    r = c.post("/api/firewall/connect",
               json={"host": "192.0.2.1", "user": "admin", "password": "pw", "verify_tls": False})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["connected"] is True
    assert body["sw_version"] == "11.1.4-h7"
    # Key persisted (DPAPI-wrapped or raw fallback) but never echoed back.
    assert "FAKEKEY123" not in r.text
    assert store.get("fw_api_key")


def test_firewall_status_and_settings_redaction(client, monkeypatch):
    c, store = client
    monkeypatch.setattr(panos_api, "generate_api_key", lambda *a, **k: "SECRETKEY")
    monkeypatch.setattr(panos_api, "FirewallClient", _FakeClient)
    c.post("/api/firewall/connect",
           json={"host": "192.0.2.1", "user": "admin", "password": "pw", "verify_tls": True})

    status = c.get("/api/firewall/status").json()
    assert status["connected"] is True
    assert status["hostname"] == "fw-edge-01"

    # /api/settings must never leak the firewall key.
    settings = c.get("/api/settings").json()["settings"]
    assert "fw_api_key" not in settings
    assert settings["fw_connected"] is True


def test_firewall_op_whitelist(client, monkeypatch):
    c, store = client
    store["fw_host"] = "192.0.2.1"
    store["fw_api_key"] = "K"
    monkeypatch.setattr(panos_api, "FirewallClient", _FakeClient)
    # A non-show/test op must be rejected before any device call.
    r = c.post("/api/firewall/op", json={"op_xml": "<request><restart/></request>"})
    assert r.status_code == 400


def test_firewall_test_offline_returns_cli(client):
    c, _ = client  # not connected
    r = c.post("/api/firewall/test", json={
        "kind": "security-policy-match",
        "params": {"source": "10.0.0.5", "destination": "8.8.8.8", "destination_port": 443},
    })
    assert r.status_code == 200
    body = r.json()
    assert body["ran"] is False
    assert "test security-policy-match" in body["cli"]


def test_firewall_test_bad_params(client):
    c, _ = client
    r = c.post("/api/firewall/test", json={"kind": "security-policy-match",
                                           "params": {"source": "bad", "destination": "8.8.8.8"}})
    assert r.status_code == 400

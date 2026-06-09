"""Security regression tests for the license server (license_server/app.py).

Covers Phase-1 hardening:
  S2 — _real_ip uses trusted-hop logic (spoofed leftmost XFF ignored)
  S4 — CORS no longer allows the "null" origin
  S5 — /tmp DB on Render fails loud
  S3 — key deliveries are audited
  (regression) webhook HMAC signature still enforced
"""
import hashlib
import hmac
import json
import os
import subprocess
import sys
from types import SimpleNamespace

from fastapi.testclient import TestClient

import app  # noqa: E402  (env + path set up in conftest.py)


def _fake_request(xff=None, peer="10.0.0.9"):
    headers = {}
    if xff is not None:
        headers["X-Forwarded-For"] = xff
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=peer))


# ---------------------------------------------------------------------------
# S2 — X-Forwarded-For trust
# ---------------------------------------------------------------------------
def test_real_ip_ignores_spoofed_leftmost(monkeypatch):
    monkeypatch.setattr(app, "TRUSTED_PROXY_HOPS", 1)
    # Attacker prepends a fake IP; the trusted proxy appended the real one last.
    req = _fake_request(xff="9.9.9.9, 203.0.113.50")
    assert app._real_ip(req) == "203.0.113.50"


def test_real_ip_single_value(monkeypatch):
    monkeypatch.setattr(app, "TRUSTED_PROXY_HOPS", 1)
    assert app._real_ip(_fake_request(xff="203.0.113.50")) == "203.0.113.50"


def test_real_ip_falls_back_to_peer():
    assert app._real_ip(_fake_request(xff=None, peer="10.1.2.3")) == "10.1.2.3"


def test_real_ip_respects_two_hops(monkeypatch):
    monkeypatch.setattr(app, "TRUSTED_PROXY_HOPS", 2)
    # With 2 trusted hops the real client is the 2nd entry from the right
    # (ProxyFix x_for=2 semantics); 1.2.3.4 is spoofed, 10.0.0.1 is the inner proxy.
    req = _fake_request(xff="1.2.3.4, 203.0.113.50, 10.0.0.1")
    assert app._real_ip(req) == "203.0.113.50"


# ---------------------------------------------------------------------------
# S4 — CORS
# ---------------------------------------------------------------------------
def test_cors_rejects_null_origin():
    client = TestClient(app.app)
    r = client.get("/health", headers={"Origin": "null"})
    assert r.headers.get("access-control-allow-origin") != "null"


def test_cors_allows_loopback_origin():
    client = TestClient(app.app)
    r = client.get("/health", headers={"Origin": "http://127.0.0.1:8000"})
    assert r.headers.get("access-control-allow-origin") == "http://127.0.0.1:8000"


# ---------------------------------------------------------------------------
# S5 — DB path guard (subprocess: env read at import time)
# ---------------------------------------------------------------------------
def test_tmp_db_on_render_fails_loud():
    env = dict(os.environ)
    env["RENDER"] = "true"
    env["DB_PATH"] = "/tmp/should_refuse.db"
    env.pop("ALLOW_EPHEMERAL_DB", None)
    ls_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [sys.executable, "-c", "import app"],
        cwd=ls_dir, env=env, capture_output=True, text=True,
    )
    assert proc.returncode != 0
    assert "persistent disk" in (proc.stderr + proc.stdout)


def test_tmp_db_allowed_with_override():
    env = dict(os.environ)
    env["RENDER"] = "true"
    env["DB_PATH"] = "/tmp/ok_ephemeral.db"
    env["ALLOW_EPHEMERAL_DB"] = "1"
    ls_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [sys.executable, "-c", "import app"],
        cwd=ls_dir, env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 0


# ---------------------------------------------------------------------------
# S3 — key delivery auditing + anomaly log
# ---------------------------------------------------------------------------
def test_register_and_login_record_key_delivery():
    client = TestClient(app.app)
    email = "audit-test@example.com"
    # Clean any prior run.
    with app.get_db() as db:
        uid = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if uid:
            db.execute("DELETE FROM key_deliveries WHERE user_id=?", (uid["id"],))
            db.execute("DELETE FROM users WHERE email=?", (email,))
            db.commit()

    r = client.post("/auth/register", json={"email": email, "password": "password123"})
    assert r.status_code == 200, r.text
    assert r.json().get("anthropic_key")  # free tier still gets the (encrypted) key

    with app.get_db() as db:
        uid = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
        n = db.execute(
            "SELECT COUNT(*) AS c FROM key_deliveries WHERE user_id=?", (uid,)
        ).fetchone()["c"]
    assert n >= 1


# ---------------------------------------------------------------------------
# regression — webhook signature still enforced
# ---------------------------------------------------------------------------
def test_webhook_rejects_bad_signature():
    client = TestClient(app.app)
    body = json.dumps({"meta": {"event_name": "subscription_created"}}).encode()
    r = client.post("/webhook/lemonsqueezy", content=body,
                    headers={"X-Signature": "deadbeef"})
    assert r.status_code == 401


def test_webhook_accepts_valid_signature():
    client = TestClient(app.app)
    payload = {
        "meta": {"event_name": "subscription_created"},
        "data": {"attributes": {"user_email": "wh@example.com", "variant_name": "pro"}},
    }
    body = json.dumps(payload).encode()
    sig = hmac.new(b"test-webhook-secret", body, hashlib.sha256).hexdigest()
    r = client.post("/webhook/lemonsqueezy", content=body, headers={"X-Signature": sig})
    assert r.status_code == 200, r.text
    assert r.json().get("ok") is True

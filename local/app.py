"""
ADK Cyber AI - Local Desktop Backend v4.0
=========================================
Session-based auth. ADK Cyber's Anthropic key is returned by the license server
after login and cached in memory — never written to disk.

Data flow:
  Login/register:    Your machine  → license_server.railway.app
  Chat queries:      Your machine  → api.anthropic.com  (directly, using ADK key)
  Config text:       Stays on your machine + goes to Anthropic only

Nothing about your firewall configs ever touches ADK Cyber's servers.
"""

import base64
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# App version — replaced by CI at build time
# ---------------------------------------------------------------------------
APP_VERSION = "0.0.0"

import anthropic
import httpx
from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel, validator

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

CONFIG_DIR  = Path.home() / ".pan_copilot"
CONFIG_FILE = CONFIG_DIR / "config.json"
DB_PATH     = CONFIG_DIR / "conversations.db"

def _base() -> Path:
    if getattr(sys, "_MEIPASS", None):
        return Path(sys._MEIPASS)
    return Path(__file__).parent

FRONTEND_PATH      = _base() / "pan_copilot_desktop.html"
SYSTEM_PROMPT_PATH = _base() / "PAN_Copilot_Master_System_Prompt.md"

# ---------------------------------------------------------------------------
# License server URL
# ---------------------------------------------------------------------------

_raw_license_url = os.environ.get("PAN_COPILOT_LICENSE_URL", "https://pan-copilot.onrender.com")
import urllib.parse as _urlparse
_parsed = _urlparse.urlparse(_raw_license_url)
if _parsed.scheme != "https":
    raise ValueError(f"PAN_COPILOT_LICENSE_URL must use https://, got: {_raw_license_url}")
LICENSE_SERVER_URL = _raw_license_url

# ---------------------------------------------------------------------------
# Shutdown token — generated at startup, required by /api/shutdown
# ---------------------------------------------------------------------------
SHUTDOWN_TOKEN = secrets.token_hex(32)

# ---------------------------------------------------------------------------
# API key decryption (matches license_server encryption via HKDF + Fernet)
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
    from cryptography.hazmat.primitives import hashes as _crypto_hashes
    from cryptography.fernet import Fernet as _Fernet
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False

def _decrypt_api_key(encrypted: str, session_token: str) -> Optional[str]:
    if not _CRYPTO_OK or not encrypted or not session_token:
        return encrypted  # fallback: treat as plaintext
    try:
        hkdf = _HKDF(
            algorithm=_crypto_hashes.SHA256(),
            length=32,
            salt=b"pan-copilot-apikey-v1",
            info=b"api-key-encryption",
        )
        key = base64.urlsafe_b64encode(hkdf.derive(session_token.encode()))
        return _Fernet(key).decrypt(encrypted.encode()).decode()
    except Exception:
        return None  # decryption failed — key not usable

# ---------------------------------------------------------------------------
# Session token encryption via Windows DPAPI
# ---------------------------------------------------------------------------
def _protect_token(token: str) -> str:
    """Encrypt token with Windows DPAPI (user-scoped). Falls back to plaintext."""
    try:
        import win32crypt
        encrypted = win32crypt.CryptProtectData(token.encode(), None, None, None, None, 0)
        return "dpapi:" + base64.b64encode(encrypted).decode()
    except Exception:
        return token

def _unprotect_token(stored: str) -> str:
    """Decrypt DPAPI-protected token. Falls back to treating as plaintext."""
    if not stored.startswith("dpapi:"):
        return stored
    try:
        import win32crypt
        encrypted = base64.b64decode(stored[6:])
        _, decrypted = win32crypt.CryptUnprotectData(encrypted, None, None, None, 0)
        return decrypted.decode()
    except Exception:
        return stored  # return raw if decryption fails

# ---------------------------------------------------------------------------
# In-memory session cache
# The Anthropic API key from ADK Cyber is NEVER written to disk.
# It lives only in this dict for the duration of the process.
# ---------------------------------------------------------------------------

_session_cache: dict = {
    "token": None,
    "email": None,
    "tier": None,            # free | pro | max
    "anthropic_key": None,   # ADK Cyber's key — memory only
    "period": "weekly",      # weekly (free) | monthly (pro/team)
    "queries_used": 0,
    "queries_limit": 10,
    "queries_remaining": 10,
    # Legacy aliases kept for backward compat
    "weekly_used": 0,
    "weekly_limit": 10,
}

# ---------------------------------------------------------------------------
# Config — stores session token only (not the API key)
# ---------------------------------------------------------------------------

def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if "session_token" in raw:
                raw["session_token"] = _unprotect_token(raw["session_token"])
            return raw
        except Exception:
            return {}
    return {}

def save_config(data: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    stored = dict(data)
    if "session_token" in stored and stored["session_token"]:
        stored["session_token"] = _protect_token(stored["session_token"])
    CONFIG_FILE.write_text(json.dumps(stored, indent=2), encoding="utf-8")
    # Restrict file to owner read/write only (best-effort on Windows)
    try:
        import stat
        CONFIG_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="ADK Cyber AI", version="4.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://127.0.0.1",
        "null",
    ],
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Database — conversations
# ---------------------------------------------------------------------------

def get_db():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS conversations (
                id         TEXT PRIMARY KEY,
                title      TEXT NOT NULL DEFAULT 'New conversation',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id              TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                role            TEXT NOT NULL,
                content         TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id)
            );
        """)
        db.commit()

init_db()

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

def load_system_prompt() -> str:
    if SYSTEM_PROMPT_PATH.exists():
        raw = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
        marker = "## SYSTEM PROMPT (COPY EVERYTHING BELOW THIS LINE)"
        if marker in raw:
            return re.sub(r"^[\s\-]+", "", raw.split(marker, 1)[1]).strip()
        return raw.strip()
    return (
        "You are ADK Cyber AI, an expert AI assistant for Palo Alto Networks engineers. "
        "You have deep knowledge of the full PAN portfolio including PAN-OS 8.x through 11.x, "
        "Panorama, Cortex XDR, XSIAM, XSOAR, Prisma Access, Prisma Cloud, Prisma SD-WAN, "
        "GlobalProtect, WildFire, Advanced Threat Prevention, DNS Security, URL Filtering, "
        "Strata Cloud Manager, and AI Runtime Security. "
        "Be direct, precise, and practical. When the user pastes config or CLI output, "
        "analyze it carefully before answering."
    )

SYSTEM_PROMPT = load_system_prompt()

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AuthRequest(BaseModel):
    email: str
    password: str

class Message(BaseModel):
    role: str
    content: str

_ALLOWED_MODELS = {
    "auto",
    "claude-opus-4-7",
    "claude-sonnet-4-6",
    "claude-haiku-4-5-20251001",
}
_MAX_TOKENS_CAP = 4096

# ---------------------------------------------------------------------------
# Model routing — picks the best model based on question complexity
# ---------------------------------------------------------------------------

_COMPLEX_KEYWORDS = {
    "audit", "analyze", "analyse", "review", "migrate", "migration",
    "shadow", "rulebase", "rule base", "security posture", "convert",
    "compliance", "assessment", "inventory", "all rules", "all policies",
    "best practices", "troubleshoot", "diagnose", "forensic",
}

def _select_model(message: str, config_text: Optional[str]) -> str:
    """Route to the right model based on message and config complexity."""
    config_len = len(config_text or "")
    msg_lower  = message.lower()
    has_keyword = any(kw in msg_lower for kw in _COMPLEX_KEYWORDS)

    # Large config paste → deep analysis needed
    if config_len > 5000:
        return "claude-opus-4-7"
    # Complex keyword + any config → Opus
    if config_len > 0 and has_keyword:
        return "claude-opus-4-7"
    # Any config pasted → at least Sonnet
    if config_len > 0:
        return "claude-sonnet-4-6"
    # Complex keyword or long question → Sonnet
    if has_keyword or len(message) > 200:
        return "claude-sonnet-4-6"
    # Short simple question → Haiku
    return "claude-haiku-4-5-20251001"


class ChatRequest(BaseModel):
    message: str
    config_text: Optional[str] = None
    history: Optional[list[Message]] = []
    model: Optional[str] = "auto"
    max_tokens: Optional[int] = 2048
    conversation_id: Optional[str] = None

    @validator("model", pre=True, always=True)
    def validate_model(cls, v):
        if v not in _ALLOWED_MODELS:
            return "auto"
        return v

    @validator("max_tokens", pre=True, always=True)
    def cap_tokens(cls, v):
        return min(int(v or 2048), _MAX_TOKENS_CAP)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def build_messages(req: ChatRequest) -> list:
    messages = []
    for turn in (req.history or []):
        if turn.role in ("user", "assistant"):
            messages.append({"role": turn.role, "content": turn.content})
    user_content = req.message
    if req.config_text and req.config_text.strip():
        user_content = (
            "I am pasting the following PAN-OS configuration or CLI output for you to analyze:\n\n"
            f"```\n{req.config_text.strip()}\n```\n\n"
            f"{req.message}"
        )
    messages.append({"role": "user", "content": user_content})
    return messages

def get_or_create_conversation(conversation_id: Optional[str]) -> str:
    if conversation_id:
        with get_db() as db:
            row = db.execute(
                "SELECT id FROM conversations WHERE id = ?", (conversation_id,)
            ).fetchone()
        if row:
            return conversation_id
    new_id = str(uuid.uuid4())
    ts = now_iso()
    with get_db() as db:
        db.execute(
            "INSERT INTO conversations (id, title, created_at, updated_at) VALUES (?,?,?,?)",
            (new_id, "New conversation", ts, ts)
        )
        db.commit()
    return new_id

def save_messages(conversation_id: str, user_msg: str, assistant_msg: str):
    ts = now_iso()
    with get_db() as db:
        db.execute(
            "INSERT INTO messages (id, conversation_id, role, content, created_at) VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), conversation_id, "user", user_msg, ts)
        )
        db.execute(
            "INSERT INTO messages (id, conversation_id, role, content, created_at) VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), conversation_id, "assistant", assistant_msg, ts)
        )
        db.execute(
            "UPDATE conversations SET updated_at = ? WHERE id = ?", (ts, conversation_id)
        )
        db.commit()

def auto_title(conversation_id: str, first_message: str):
    title = first_message.strip().replace("\n", " ")[:60]
    if len(first_message.strip()) > 60:
        title += "…"
    with get_db() as db:
        count = db.execute(
            "SELECT COUNT(*) FROM messages WHERE conversation_id = ?", (conversation_id,)
        ).fetchone()[0]
        if count <= 2:
            db.execute(
                "UPDATE conversations SET title = ? WHERE id = ?", (title, conversation_id)
            )
            db.commit()

# ---------------------------------------------------------------------------
# Config sanitization — strip credential values before sending to Anthropic
# ---------------------------------------------------------------------------

_SENSITIVE_XML_TAGS = (
    "phash", "password", "password-hash", "secret", "shared-secret",
    "pre-shared-key", "auth-key", "authentication-key", "api-key",
    "private-key", "passphrase", "bind-password", "community", "key",
)

_CLI_SET_KEYWORDS = (
    "password", "secret", "pre-shared-key", "shared-secret",
    "auth-key", "authentication-key", "api-key", "passphrase",
    "bind-password", "community",
)

_CLI_DISPLAY_KEYWORDS = (
    "password", "secret", "shared-secret", "pre-shared-key",
    "auth-key", "authentication-key", "api-key", "passphrase",
    "bind-password", "community", "phash",
)


def _build_sanitize_patterns():
    """Compile regex patterns once at startup."""
    patterns = []

    # XML / candidate-config: <tag>value</tag> (single-line values)
    for tag in _SENSITIVE_XML_TAGS:
        patterns.append((
            re.compile(
                rf"(<{re.escape(tag)}>)[^<]+(</{re.escape(tag)}>)",
                re.IGNORECASE,
            ),
            r"\1[REDACTED]\2",
        ))

    # PEM private key blocks (multi-line)
    patterns.append((
        re.compile(
            r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )?PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        "[PRIVATE KEY REDACTED]",
    ))

    # CLI set format: "set ... <keyword> <value>"
    patterns.append((
        re.compile(
            r"(?m)(^\s*set\s+\S.*?\s+(?:"
            + "|".join(re.escape(k) for k in _CLI_SET_KEYWORDS)
            + r")\s+)\S+",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ))

    # CLI display / show output: "keyword: value"
    patterns.append((
        re.compile(
            r"(?m)(^\s*(?:"
            + "|".join(re.escape(k) for k in _CLI_DISPLAY_KEYWORDS)
            + r")\s*:\s*)\S+",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ))

    return patterns


_SANITIZE_PATTERNS = _build_sanitize_patterns()


def sanitize_config_text(text: str):
    """Strip credential values from PAN-OS config/CLI output.

    Returns (sanitized_text, redaction_count). Only credential *values*
    are removed — IPs, zones, policy rules, and all structural tags are
    preserved so the AI can still diagnose configuration problems.
    """
    count = 0
    for pattern, replacement in _SANITIZE_PATTERNS:
        text, n = pattern.subn(replacement, text)
        count += n
    return text, count


# ---------------------------------------------------------------------------
# License server calls
# ---------------------------------------------------------------------------

def _license_post(path: str, body: dict) -> dict:
    # Render free tier can take up to 60 s to wake from sleep — use a generous
    # timeout so the first sign-in after inactivity doesn't fail.
    try:
        r = httpx.post(
            f"{LICENSE_SERVER_URL}{path}",
            json=body,
            timeout=60.0,
        )
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as e:
        detail = "Unknown error"
        try:
            detail = e.response.json().get("detail", detail)
        except Exception:
            pass
        raise HTTPException(status_code=e.response.status_code, detail=detail)
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="License server unreachable. If this is your first sign-in today, wait 30 seconds and try again."
        )

def _populate_session(data: dict):
    """Write license server response into the in-memory session cache."""
    token = data.get("token") or _session_cache["token"]
    _session_cache["token"]        = token
    _session_cache["email"]        = data.get("email")
    _session_cache["tier"]         = data.get("tier", "free")
    _session_cache["period"]       = data.get("period", "weekly")
    _session_cache["queries_used"]      = data.get("queries_used", 0) or 0
    _session_cache["queries_limit"]     = data.get("queries_limit", 10) or 10
    _session_cache["queries_remaining"] = data.get("queries_remaining", 10) or 10
    _session_cache["weekly_used"]  = data.get("weekly_used") or data.get("queries_used", 0) or 0
    _session_cache["weekly_limit"] = data.get("weekly_limit") or data.get("queries_limit", 10) or 10

    # Decrypt the API key using the session token as key material
    encrypted_key = data.get("anthropic_key")
    if encrypted_key and token:
        _session_cache["anthropic_key"] = _decrypt_api_key(encrypted_key, token)
    else:
        _session_cache["anthropic_key"] = None

# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.post("/api/auth/register")
def register(req: AuthRequest):
    data = _license_post("/auth/register", {"email": req.email, "password": req.password})
    _populate_session(data)
    cfg = load_config()
    cfg["session_token"] = data["token"]
    cfg["session_email"] = data["email"]
    save_config(cfg)
    return {
        "ok": True,
        "email": data["email"],
        "tier": data["tier"],
        "period": data.get("period", "weekly"),
        "queries_used": data.get("queries_used", 0),
        "queries_limit": data.get("queries_limit", 10),
        "queries_remaining": data.get("queries_remaining", 10),
    }

@app.post("/api/auth/login")
def login(req: AuthRequest):
    data = _license_post("/auth/login", {"email": req.email, "password": req.password})
    _populate_session(data)
    cfg = load_config()
    cfg["session_token"] = data["token"]
    cfg["session_email"] = data["email"]
    save_config(cfg)
    return {
        "ok": True,
        "email": data["email"],
        "tier": data["tier"],
        "period": data.get("period", "weekly"),
        "queries_used": data.get("queries_used", 0),
        "queries_limit": data.get("queries_limit", 10),
        "queries_remaining": data.get("queries_remaining", 10),
    }

@app.post("/api/auth/logout")
def logout():
    _session_cache.update({"token": None, "email": None, "tier": None, "anthropic_key": None})
    cfg = load_config()
    cfg.pop("session_token", None)
    cfg.pop("session_email", None)
    save_config(cfg)
    return {"ok": True}

@app.get("/api/auth/status")
def auth_status():
    """
    Called on app startup. Validates saved token with the license server
    and restores the ADK Anthropic key into memory.
    """
    cfg = load_config()
    token = cfg.get("session_token")
    if not token:
        return {"authenticated": False}

    _session_cache["token"] = token

    try:
        data = _license_post("/auth/validate", {"token": token})
        _populate_session(data)
        _session_cache["token"] = token
        return {
            "authenticated": True,
            "email": data["email"],
            "tier": data["tier"],
            "period": data.get("period", "weekly"),
            "queries_used": data.get("queries_used", 0),
            "queries_limit": data.get("queries_limit", 10),
            "queries_remaining": data.get("queries_remaining", 10),
        }
    except HTTPException:
        cfg.pop("session_token", None)
        cfg.pop("session_email", None)
        save_config(cfg)
        _session_cache["token"] = None
        return {"authenticated": False}

# ---------------------------------------------------------------------------
# Conversation endpoints
# ---------------------------------------------------------------------------

def _require_session():
    if not _session_cache.get("token"):
        raise HTTPException(status_code=401, detail="Not logged in.")

@app.get("/conversations")
def list_conversations():
    _require_session()
    with get_db() as db:
        rows = db.execute(
            "SELECT id, title, updated_at FROM conversations ORDER BY updated_at DESC LIMIT 50"
        ).fetchall()
    return [dict(r) for r in rows]

@app.get("/conversations/{conv_id}")
def get_conversation(conv_id: str):
    _require_session()
    with get_db() as db:
        conv = db.execute(
            "SELECT * FROM conversations WHERE id = ?", (conv_id,)
        ).fetchone()
        if not conv:
            raise HTTPException(status_code=404, detail="Conversation not found.")
        msgs = db.execute(
            "SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY created_at ASC",
            (conv_id,)
        ).fetchall()
    return {"conversation": dict(conv), "messages": [dict(m) for m in msgs]}

@app.delete("/conversations/{conv_id}")
def delete_conversation(conv_id: str):
    _require_session()
    with get_db() as db:
        db.execute("DELETE FROM messages WHERE conversation_id = ?", (conv_id,))
        db.execute("DELETE FROM conversations WHERE id = ?", (conv_id,))
        db.commit()
    return {"deleted": conv_id}

# ---------------------------------------------------------------------------
# File upload
# ---------------------------------------------------------------------------

@app.post("/upload")
async def upload_config(file: UploadFile = File(...)):
    allowed = {".txt", ".xml", ".log", ".cfg", ".conf"}
    ext = Path(file.filename).suffix.lower()
    if ext not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(allowed)}"
        )
    MAX_BYTES = 500_000
    content = await file.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="File too large. Max 500 KB.")
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file as text.")
    return {"filename": file.filename, "size": len(content), "text": text}

# ---------------------------------------------------------------------------
# Chat — streaming
# ---------------------------------------------------------------------------

@app.post("/chat/stream")
def chat_stream(req: ChatRequest):
    if not _session_cache.get("token"):
        raise HTTPException(
            status_code=401,
            detail="Not logged in. Please sign in to use ADK Cyber AI."
        )

    api_key = _session_cache.get("anthropic_key")
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Session key missing. Please log out and log back in."
        )

    token = _session_cache["token"]

    # Check/increment query count via license server
    check = _license_post("/query/check", {"token": token})

    if not check.get("allowed", False):
        raise HTTPException(
            status_code=429,
            detail=check.get(
                "detail",
                f"Query limit reached. Upgrade at adkcyber.com/adk-cyber-ai.html"
            )
        )

    # Sync usage into session cache
    for key in ("queries_used", "queries_limit", "queries_remaining", "period"):
        if check.get(key) is not None:
            _session_cache[key] = check[key]
    if check.get("weekly_used") is not None:
        _session_cache["weekly_used"] = check["weekly_used"]

    # Strip credential values from config and message before sending to Anthropic
    cfg_sanitized, cfg_redactions = (
        sanitize_config_text(req.config_text)
        if req.config_text and req.config_text.strip()
        else (req.config_text or "", 0)
    )
    msg_sanitized, msg_redactions = sanitize_config_text(req.message)
    total_redactions = cfg_redactions + msg_redactions
    sanitized_req = req.copy(update={
        "config_text": cfg_sanitized,
        "message":     msg_sanitized,
    })

    conv_id  = get_or_create_conversation(req.conversation_id)
    messages = build_messages(sanitized_req)
    client   = anthropic.Anthropic(api_key=api_key)

    # Resolve model: "auto" → pick based on complexity
    resolved_model = (
        _select_model(req.message, req.config_text)
        if req.model == "auto"
        else req.model
    )

    def event_generator():
        full_reply = []
        try:
            with client.messages.stream(
                model=resolved_model,
                max_tokens=req.max_tokens,
                system=SYSTEM_PROMPT,
                messages=messages,
            ) as stream:
                for text in stream.text_stream:
                    full_reply.append(text)
                    yield f"data: {json.dumps({'type': 'token', 'text': text})}\n\n"
                final = stream.get_final_message()
                reply_text = "".join(full_reply)
                save_messages(conv_id, req.message, reply_text)
                auto_title(conv_id, req.message)
                yield f"data: {json.dumps({'type': 'done', 'model': resolved_model, 'input_tokens': final.usage.input_tokens, 'output_tokens': final.usage.output_tokens, 'conversation_id': conv_id, 'queries_used': _session_cache.get('queries_used'), 'queries_limit': _session_cache.get('queries_limit'), 'queries_remaining': _session_cache.get('queries_remaining'), 'period': _session_cache.get('period', 'weekly'), 'tier': _session_cache.get('tier'), 'redactions': total_redactions})}\n\n"
        except anthropic.AuthenticationError:
            yield f"data: {json.dumps({'type': 'error', 'detail': 'API key error. Please contact support@adkcyber.com.'})}\n\n"
        except anthropic.RateLimitError:
            yield f"data: {json.dumps({'type': 'error', 'detail': 'Rate limit reached. Try again in a moment.'})}\n\n"
        except anthropic.APIError as e:
            yield f"data: {json.dumps({'type': 'error', 'detail': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

# ---------------------------------------------------------------------------
# Auto-update
# ---------------------------------------------------------------------------

_VERSION_JSON_URL = "https://downloads.adkcyber.com/version.json"
_update_cache: dict = {}
_update_cache_ts: float = 0.0
_UPDATE_CACHE_TTL = 3600.0  # re-check at most once per hour


def _parse_version(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.lstrip("v").split("."))
    except Exception:
        return (0, 0, 0)


def _fetch_update_info() -> dict:
    global _update_cache, _update_cache_ts
    now = time.time()
    if _update_cache and now - _update_cache_ts < _UPDATE_CACHE_TTL:
        return _update_cache
    try:
        r = httpx.get(_VERSION_JSON_URL, timeout=5.0, follow_redirects=True)
        r.raise_for_status()
        data = r.json()
        latest = data.get("version", APP_VERSION)
        installer_url = data.get("installer_url", "")
        _update_cache = {
            "current_version": APP_VERSION,
            "latest_version": latest,
            "update_available": _parse_version(latest) > _parse_version(APP_VERSION),
            "installer_url": installer_url,
        }
        _update_cache_ts = now
    except Exception:
        _update_cache = {
            "current_version": APP_VERSION,
            "latest_version": APP_VERSION,
            "update_available": False,
            "installer_url": "",
        }
        _update_cache_ts = now
    return _update_cache


@app.get("/api/version")
def get_version():
    return _fetch_update_info()


@app.post("/api/update")
def install_update():
    info = _fetch_update_info()
    if not info.get("update_available"):
        raise HTTPException(status_code=400, detail="No update available.")
    installer_url = info.get("installer_url", "")
    if not installer_url.startswith("https://downloads.adkcyber.com/"):
        raise HTTPException(status_code=400, detail="Invalid installer source.")

    def _download_and_run():
        try:
            r = httpx.get(installer_url, timeout=180.0, follow_redirects=True)
            r.raise_for_status()
            version = info.get("latest_version", "update")
            tmp = Path(tempfile.gettempdir()) / f"PAN_Copilot_Setup_{version}.exe"
            tmp.write_bytes(r.content)

            # Launch installer first, then shut down this process so the installer
            # can overwrite all bundled files without hitting locked-file errors.
            subprocess.Popen([str(tmp), "/SILENT", "/RESTARTAPPLICATIONS"])

            # Give the installer process a moment to start up.
            time.sleep(1.5)

            # Signal uvicorn to stop gracefully — the frontend polls /health and
            # calls window.close() when it sees the server go away.
            if _uvicorn_server:
                _uvicorn_server.should_exit = True

            # Hard-exit after 4 s as a safety net to guarantee all file locks
            # held by this process are released before the installer overwrites them.
            def _force_exit():
                time.sleep(4.0)
                os._exit(0)
            threading.Thread(target=_force_exit, daemon=True).start()

        except Exception:
            pass

    threading.Thread(target=_download_and_run, daemon=True).start()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Health + frontend
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": APP_VERSION,
        "mode": "local",
        "authenticated": _session_cache.get("email") is not None,
    }

_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "connect-src 'self'; "
    "img-src 'self' data: blob:; "
    "font-src 'self' data:; "
    "object-src 'none'; "
    "frame-src 'none'; "
    "base-uri 'self';"
)

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    if not FRONTEND_PATH.exists():
        return HTMLResponse("<h1>ADK Cyber AI</h1><p>Frontend not found.</p>", status_code=404)
    html = FRONTEND_PATH.read_text(encoding="utf-8")
    # Inject shutdown token as a JS global so sendBeacon can authenticate
    inject = f'<script>window.__SHUTDOWN_TOKEN__="{SHUTDOWN_TOKEN}";</script>'
    html = html.replace("</head>", inject + "\n</head>", 1)
    return HTMLResponse(content=html, headers={"Content-Security-Policy": _CSP})


# ---------------------------------------------------------------------------
# Graceful shutdown endpoint
# ---------------------------------------------------------------------------
_uvicorn_server = None

class ShutdownRequest(BaseModel):
    shutdown_token: str = ""

@app.post("/api/shutdown")
def request_shutdown(req: ShutdownRequest):
    import hmac as _hmac
    if not _hmac.compare_digest(req.shutdown_token, SHUTDOWN_TOKEN):
        raise HTTPException(status_code=403, detail="Forbidden.")
    import threading
    def _do_exit():
        import time
        time.sleep(0.4)
        if _uvicorn_server is not None:
            _uvicorn_server.should_exit = True
    threading.Thread(target=_do_exit, daemon=True).start()
    return {"ok": True}
"""
PAN Copilot - Local Desktop Backend v4.0
=========================================
Session-based auth. ADK Cyber's Anthropic key is returned by the license server
after login and cached in memory — never written to disk.

Data flow:
  Login/register:    Your machine  → license_server.railway.app
  Chat queries:      Your machine  → api.anthropic.com  (directly, using ADK key)
  Config text:       Stays on your machine + goes to Anthropic only

Nothing about your firewall configs ever touches ADK Cyber's servers.
"""

import json
import os
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import anthropic
import httpx
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel

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

LICENSE_SERVER_URL = os.environ.get(
    "PAN_COPILOT_LICENSE_URL",
    "https://pan-copilot.onrender.com"
)

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
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_config(data: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="PAN Copilot", version="4.0.0")

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
        "You are PAN Copilot, an expert AI assistant for Palo Alto Networks engineers. "
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

class ChatRequest(BaseModel):
    message: str
    config_text: Optional[str] = None
    history: Optional[list[Message]] = []
    model: Optional[str] = "claude-sonnet-4-6"
    max_tokens: Optional[int] = 2048
    conversation_id: Optional[str] = None

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
# License server calls
# ---------------------------------------------------------------------------

def _license_post(path: str, body: dict) -> dict:
    try:
        r = httpx.post(
            f"{LICENSE_SERVER_URL}{path}",
            json=body,
            timeout=10.0,
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
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"License server unreachable: {str(e)}")

def _populate_session(data: dict):
    """Write license server response into the in-memory session cache."""
    _session_cache["token"]         = data.get("token") or _session_cache["token"]
    _session_cache["email"]         = data.get("email")
    _session_cache["tier"]          = data.get("tier", "free")
    _session_cache["anthropic_key"] = data.get("anthropic_key")
    _session_cache["period"]        = data.get("period", "weekly")
    _session_cache["queries_used"]       = data.get("queries_used", 0) or 0
    _session_cache["queries_limit"]      = data.get("queries_limit", 10) or 10
    _session_cache["queries_remaining"]  = data.get("queries_remaining", 10) or 10
    # Legacy aliases
    _session_cache["weekly_used"]   = data.get("weekly_used") or data.get("queries_used", 0) or 0
    _session_cache["weekly_limit"]  = data.get("weekly_limit") or data.get("queries_limit", 10) or 10

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

@app.get("/conversations")
def list_conversations():
    with get_db() as db:
        rows = db.execute(
            "SELECT id, title, updated_at FROM conversations ORDER BY updated_at DESC LIMIT 50"
        ).fetchall()
    return [dict(r) for r in rows]

@app.get("/conversations/{conv_id}")
def get_conversation(conv_id: str):
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
            detail="Not logged in. Please sign in to use PAN Copilot."
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
                f"Query limit reached. Upgrade at adkcyber.com/pan-copilot.html"
            )
        )

    # Sync usage into session cache
    for key in ("queries_used", "queries_limit", "queries_remaining", "period"):
        if check.get(key) is not None:
            _session_cache[key] = check[key]
    if check.get("weekly_used") is not None:
        _session_cache["weekly_used"] = check["weekly_used"]

    conv_id  = get_or_create_conversation(req.conversation_id)
    messages = build_messages(req)
    client   = anthropic.Anthropic(api_key=api_key)

    def event_generator():
        full_reply = []
        try:
            with client.messages.stream(
                model=req.model,
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
                yield f"data: {json.dumps({'type': 'done', 'input_tokens': final.usage.input_tokens, 'output_tokens': final.usage.output_tokens, 'conversation_id': conv_id, 'queries_used': _session_cache.get('queries_used'), 'queries_limit': _session_cache.get('queries_limit'), 'queries_remaining': _session_cache.get('queries_remaining'), 'period': _session_cache.get('period', 'weekly'), 'tier': _session_cache.get('tier')})}\n\n"
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
# Health + frontend
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "4.0.0",
        "mode": "local",
        "authenticated": _session_cache.get("email") is not None,
    }

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    if FRONTEND_PATH.exists():
        return HTMLResponse(content=FRONTEND_PATH.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>PAN Copilot</h1><p>Frontend not found.</p>", status_code=404)

"""
PAN Copilot - FastAPI Backend v2.0
- Operator holds the Anthropic API key; users never need one
- Email/password auth with JWT
- Free tier: 10 queries/day | Pro tier: unlimited
- SQLite for users + conversation persistence
- File upload for PAN-OS configs (.txt, .xml, .log)
"""

import hashlib
import hmac
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")

import anthropic
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import bcrypt as _bcrypt
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
JWT_SECRET        = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM     = "HS256"
JWT_EXPIRE_DAYS   = 30
FREE_DAILY_LIMIT  = 10
LS_SIGNING_SECRET = os.environ.get("LEMONSQUEEZY_SIGNING_SECRET", "")
LS_PRO_VARIANT_ID = os.environ.get("LEMONSQUEEZY_PRO_VARIANT_ID", "")

# Fail closed: a missing JWT secret in a public-repo codebase would mean
# anyone could forge tokens for any user. Refuse to start without one.
if not JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET is not set. Refusing to start — set a long random value "
        "in the environment (e.g. `python -c \"import secrets;print(secrets.token_urlsafe(48))\"`)."
    )

# Allowed Anthropic models and output cap. Prevents a free-tier client from
# requesting an arbitrarily expensive model or an unbounded max_tokens.
ALLOWED_MODELS = {
    "claude-haiku-4-5-20251001",
    "claude-sonnet-4-6",
    "claude-opus-4-7",
}
DEFAULT_MODEL     = "claude-sonnet-4-6"
MAX_OUTPUT_TOKENS = 8192

# Cross-origin: the UI is served same-origin from this app, so the browser
# doesn't need a wildcard. Override with ALLOWED_ORIGINS (comma-separated) if
# a separate frontend host is used.
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000"
    ).split(",")
    if o.strip()
]

DB_PATH       = Path(__file__).parent / "pan_copilot.db"
FRONTEND_PATH = Path(__file__).parent.parent / "pan_copilot.html"

if not ANTHROPIC_API_KEY:
    print("WARNING: ANTHROPIC_API_KEY not set. Set it in your .env file.")

client    = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
bearer    = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="PAN Copilot API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id           TEXT PRIMARY KEY,
                email        TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                tier         TEXT NOT NULL DEFAULT 'free',
                daily_count  INTEGER NOT NULL DEFAULT 0,
                last_reset   TEXT NOT NULL DEFAULT '',
                created_at   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS conversations (
                id           TEXT PRIMARY KEY,
                user_id      TEXT NOT NULL,
                title        TEXT NOT NULL DEFAULT 'New conversation',
                product_id   TEXT,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS messages (
                id              TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                role            TEXT NOT NULL,
                content         TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id)
            );

            CREATE TABLE IF NOT EXISTS pending_upgrades (
                email      TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );
        """)
        db.commit()

init_db()

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_PATH = Path(__file__).parent.parent / "PAN_Copilot_Master_System_Prompt.md"

def load_system_prompt() -> str:
    # 1. Railway (production): read from environment variable
    env_prompt = os.environ.get("SYSTEM_PROMPT", "").strip()
    if env_prompt:
        return env_prompt

    # 2. Local development: read from the markdown file
    if SYSTEM_PROMPT_PATH.exists():
        raw = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
        marker = "## SYSTEM PROMPT (COPY EVERYTHING BELOW THIS LINE)"
        if marker in raw:
            return re.sub(r"^[\s\-]+", "", raw.split(marker, 1)[1]).strip()
        return raw.strip()

    # 3. Fallback (should not reach here in production)
    return (
        "You are PAN Copilot, an expert AI assistant for Palo Alto Networks engineers. "
        "You have deep knowledge of the full PAN portfolio. Be direct, precise, and practical."
    )

SYSTEM_PROMPT = load_system_prompt()

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

def create_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRE_DAYS)
    return jwt.encode({"sub": user_id, "exp": expire}, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

def get_user_by_id(user_id: str) -> Optional[sqlite3.Row]:
    with get_db() as db:
        return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    user_id = decode_token(creds.credentials)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")
    return user

def check_and_increment_usage(user: sqlite3.Row) -> int:
    """
    For free-tier users: enforce 10 queries/day.
    Returns remaining queries (-1 = unlimited for pro).
    Raises 429 if limit hit.
    """
    if user["tier"] == "pro":
        return -1

    today = datetime.now(timezone.utc).date().isoformat()
    count = user["daily_count"]
    last  = user["last_reset"]

    if last != today:
        count = 0

    if count >= FREE_DAILY_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Free tier limit reached ({FREE_DAILY_LIMIT} queries/day). Upgrade to Pro for unlimited access."
        )

    with get_db() as db:
        db.execute(
            "UPDATE users SET daily_count = ?, last_reset = ? WHERE id = ?",
            (count + 1, today, user["id"])
        )
        db.commit()

    return FREE_DAILY_LIMIT - (count + 1)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
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
    product_id: Optional[str] = None

class ChatResponse(BaseModel):
    reply: str
    model: str
    input_tokens: int
    output_tokens: int
    remaining_queries: int
    conversation_id: str

class ConversationSummary(BaseModel):
    id: str
    title: str
    product_id: Optional[str]
    updated_at: str

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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

def sanitize_model_and_tokens(req: ChatRequest) -> tuple[str, int]:
    """Clamp client-supplied model + max_tokens to safe bounds so a (free) user
    can't request an expensive model or an unbounded output length."""
    model = req.model if req.model in ALLOWED_MODELS else DEFAULT_MODEL
    try:
        max_tokens = int(req.max_tokens or 2048)
    except (TypeError, ValueError):
        max_tokens = 2048
    max_tokens = max(1, min(max_tokens, MAX_OUTPUT_TOKENS))
    return model, max_tokens


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def get_or_create_conversation(user_id: str, conversation_id: Optional[str], product_id: Optional[str]) -> str:
    if conversation_id:
        with get_db() as db:
            row = db.execute(
                "SELECT id FROM conversations WHERE id = ? AND user_id = ?",
                (conversation_id, user_id)
            ).fetchone()
        if row:
            return conversation_id

    new_id = str(uuid.uuid4())
    ts = now_iso()
    with get_db() as db:
        db.execute(
            "INSERT INTO conversations (id, user_id, title, product_id, created_at, updated_at) VALUES (?,?,?,?,?,?)",
            (new_id, user_id, "New conversation", product_id, ts, ts)
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
            "UPDATE conversations SET updated_at = ? WHERE id = ?",
            (ts, conversation_id)
        )
        db.commit()

def auto_title(conversation_id: str, first_message: str):
    """Set a conversation title from the first user message (first 60 chars)."""
    title = first_message.strip().replace("\n", " ")[:60]
    if len(first_message.strip()) > 60:
        title += "…"
    with get_db() as db:
        count = db.execute(
            "SELECT COUNT(*) FROM messages WHERE conversation_id = ?",
            (conversation_id,)
        ).fetchone()[0]
        if count <= 2:  # only on first exchange
            db.execute(
                "UPDATE conversations SET title = ? WHERE id = ?",
                (title, conversation_id)
            )
            db.commit()

# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.post("/auth/register")
def register(req: RegisterRequest):
    email = req.email.strip().lower()
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    with get_db() as db:
        existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="An account with that email already exists.")
        user_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO users (id, email, password_hash, tier, daily_count, last_reset, created_at) VALUES (?,?,?,?,?,?,?)",
            (user_id, email, hash_password(req.password), "free", 0, "", now_iso())
        )
        db.commit()
    token = create_token(user_id)
    return {"token": token, "email": email, "tier": "free", "remaining_queries": FREE_DAILY_LIMIT}


@app.post("/auth/login")
def login(req: LoginRequest):
    email = req.email.strip().lower()
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    token = create_token(user["id"])
    today = datetime.now(timezone.utc).date().isoformat()
    count = user["daily_count"] if user["last_reset"] == today else 0
    remaining = -1 if user["tier"] == "pro" else max(0, FREE_DAILY_LIMIT - count)
    return {"token": token, "email": user["email"], "tier": user["tier"], "remaining_queries": remaining}


@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    today = datetime.now(timezone.utc).date().isoformat()
    count = user["daily_count"] if user["last_reset"] == today else 0
    remaining = -1 if user["tier"] == "pro" else max(0, FREE_DAILY_LIMIT - count)
    return {"email": user["email"], "tier": user["tier"], "remaining_queries": remaining}

# ---------------------------------------------------------------------------
# Conversation endpoints
# ---------------------------------------------------------------------------

@app.get("/conversations")
def list_conversations(user=Depends(get_current_user)):
    with get_db() as db:
        rows = db.execute(
            "SELECT id, title, product_id, updated_at FROM conversations WHERE user_id = ? ORDER BY updated_at DESC LIMIT 50",
            (user["id"],)
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/conversations/{conv_id}")
def get_conversation(conv_id: str, user=Depends(get_current_user)):
    with get_db() as db:
        conv = db.execute(
            "SELECT * FROM conversations WHERE id = ? AND user_id = ?",
            (conv_id, user["id"])
        ).fetchone()
        if not conv:
            raise HTTPException(status_code=404, detail="Conversation not found.")
        msgs = db.execute(
            "SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY created_at ASC",
            (conv_id,)
        ).fetchall()
    return {"conversation": dict(conv), "messages": [dict(m) for m in msgs]}


@app.delete("/conversations/{conv_id}")
def delete_conversation(conv_id: str, user=Depends(get_current_user)):
    with get_db() as db:
        db.execute(
            "DELETE FROM messages WHERE conversation_id = ?", (conv_id,)
        )
        db.execute(
            "DELETE FROM conversations WHERE id = ? AND user_id = ?",
            (conv_id, user["id"])
        )
        db.commit()
    return {"deleted": conv_id}

# ---------------------------------------------------------------------------
# File upload
# ---------------------------------------------------------------------------

@app.post("/upload")
async def upload_config(file: UploadFile = File(...), user=Depends(get_current_user)):
    allowed = {".txt", ".xml", ".log", ".cfg", ".conf"}
    ext = Path(file.filename).suffix.lower()
    if ext not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(allowed)}"
        )
    MAX_BYTES = 500_000  # 500 KB
    content = await file.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="File too large. Max 500 KB.")
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file as text.")
    return {"filename": file.filename, "size": len(content), "text": text}

# ---------------------------------------------------------------------------
# Chat endpoints (protected)
# ---------------------------------------------------------------------------

@app.post("/chat")
def chat(req: ChatRequest, user=Depends(get_current_user)):
    remaining = check_and_increment_usage(user)
    conv_id = get_or_create_conversation(user["id"], req.conversation_id, req.product_id)

    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY is not configured.")
    model, max_tokens = sanitize_model_and_tokens(req)
    try:
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=SYSTEM_PROMPT,
            messages=build_messages(req),
        )
    except anthropic.AuthenticationError:
        raise HTTPException(status_code=401, detail="Anthropic API key is invalid.")
    except anthropic.RateLimitError:
        raise HTTPException(status_code=429, detail="Upstream rate limit reached. Try again in a moment.")
    except anthropic.APIError as e:
        print(f"Anthropic API error: {e}")
        raise HTTPException(status_code=502, detail="Upstream AI service error.")

    reply = response.content[0].text
    save_messages(conv_id, req.message, reply)
    auto_title(conv_id, req.message)

    return ChatResponse(
        reply=reply,
        model=response.model,
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens,
        remaining_queries=remaining,
        conversation_id=conv_id,
    )


@app.post("/chat/stream")
def chat_stream(req: ChatRequest, user=Depends(get_current_user)):
    remaining = check_and_increment_usage(user)
    conv_id = get_or_create_conversation(user["id"], req.conversation_id, req.product_id)
    messages = build_messages(req)

    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY is not configured.")
    model, max_tokens = sanitize_model_and_tokens(req)

    def event_generator():
        full_reply = []
        try:
            with client.messages.stream(
                model=model,
                max_tokens=max_tokens,
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
                yield f"data: {json.dumps({'type': 'done', 'input_tokens': final.usage.input_tokens, 'output_tokens': final.usage.output_tokens, 'remaining_queries': remaining, 'conversation_id': conv_id})}\n\n"
        except anthropic.AuthenticationError:
            yield f"data: {json.dumps({'type': 'error', 'detail': 'Invalid Anthropic API key.'})}\n\n"
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
# Health
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Lemon Squeezy webhook
# ---------------------------------------------------------------------------

@app.post("/webhooks/lemonsqueezy")
async def lemonsqueezy_webhook(request: Request):
    """
    Handles order_created and subscription_created events from Lemon Squeezy.
    Upgrades the matching user to 'pro' tier.

    Setup in LS dashboard:
      URL: https://your-domain.com/webhooks/lemonsqueezy
      Events: order_created, subscription_created
      Signing secret: set LEMONSQUEEZY_SIGNING_SECRET env var to match
    """
    body = await request.body()

    # Always verify — fail closed. Without a configured secret the endpoint is
    # disabled, so an unsigned request can never upgrade an account.
    if not LS_SIGNING_SECRET:
        raise HTTPException(status_code=503, detail="Webhook not configured.")
    sig = request.headers.get("X-Signature", "")
    expected = hmac.new(LS_SIGNING_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    event = payload.get("meta", {}).get("event_name", "")
    if event not in ("order_created", "subscription_created", "subscription_payment_success"):
        return {"status": "ignored", "event": event}

    data = payload.get("data", {})
    attrs = data.get("attributes", {})

    # Extract customer email — location differs by event type
    email = (
        attrs.get("user_email")
        or attrs.get("customer_email")
        or payload.get("meta", {}).get("custom_data", {}).get("email", "")
    )
    if not email:
        return {"status": "no_email_found"}

    email = email.strip().lower()
    with get_db() as db:
        user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            db.execute("UPDATE users SET tier = 'pro' WHERE email = ?", (email,))
            db.commit()
            return {"status": "upgraded", "email": email}
        else:
            # User hasn't registered yet — store pending upgrade so first login auto-upgrades
            db.execute(
                "INSERT OR REPLACE INTO pending_upgrades (email, created_at) VALUES (?,?)",
                (email, now_iso())
            )
            db.commit()
            return {"status": "pending", "email": email}


@app.post("/auth/upgrade-check")
def upgrade_check(user=Depends(get_current_user)):
    """Called after login — applies any pending pro upgrade for this email."""
    with get_db() as db:
        pending = db.execute(
            "SELECT email FROM pending_upgrades WHERE email = ?",
            (user["email"],)
        ).fetchone()
        if pending:
            db.execute("UPDATE users SET tier = 'pro' WHERE email = ?", (user["email"],))
            db.execute("DELETE FROM pending_upgrades WHERE email = ?", (user["email"],))
            db.commit()
            return {"upgraded": True, "tier": "pro"}
    return {"upgraded": False, "tier": user["tier"]}


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "PAN Copilot API", "version": "2.0.0"}


@app.get("/", response_class=HTMLResponse)
@app.get("/app", response_class=HTMLResponse)
def serve_frontend():
    """Serve the frontend HTML. In production the same origin handles both UI and API."""
    try:
        if FRONTEND_PATH.exists():
            content = FRONTEND_PATH.read_text(encoding="utf-8")
            return HTMLResponse(content=content)
        return HTMLResponse(
            "<h1>PAN Copilot API</h1><p>Frontend not found. Place pan_copilot.html in the project root.</p>",
            status_code=404
        )
    except Exception as e:
        print(f"Error loading frontend: {e}")
        return HTMLResponse("<h1>Error loading frontend</h1>", status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

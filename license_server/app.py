"""
PAN Copilot — License Server
============================
Lightweight FastAPI service deployed to Render.

Responsibilities:
  1. User registration / login (email + password, argon2id hashed)
  2. Session token issuance and validation
  3. Query counting with tier-appropriate limits
  4. Returning ADK Cyber's Anthropic API key (encrypted with session-token-derived key)
  5. Tier management (free / pro / max)

Data that NEVER passes through here:
  - Firewall configs
  - PAN-OS CLI output
  - Any chat message content
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pan_copilot_license")

# ---------------------------------------------------------------------------
# Config from environment variables
# ---------------------------------------------------------------------------
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
SECRET_PEPPER     = os.environ.get("SECRET_PEPPER", "change-me-in-production")
ADMIN_TOKEN       = os.environ.get("ADMIN_TOKEN", "")
LS_WEBHOOK_SECRET = os.environ.get("LS_WEBHOOK_SECRET", "")

# Startup warnings for unset critical secrets
if SECRET_PEPPER == "change-me-in-production":
    logger.critical("SECRET_PEPPER is using the default value — set a real value in your environment.")
if not LS_WEBHOOK_SECRET:
    logger.critical("LS_WEBHOOK_SECRET is not set — webhook endpoint will reject all requests.")
if not ADMIN_TOKEN:
    logger.warning("ADMIN_TOKEN is not set — admin endpoints are disabled.")
if not ANTHROPIC_API_KEY:
    logger.warning("ANTHROPIC_API_KEY is not set.")

# ---------------------------------------------------------------------------
# Password hashing — argon2id with legacy SHA-256 migration path
# ---------------------------------------------------------------------------
pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def _legacy_hash(password: str) -> str:
    return hashlib.sha256((SECRET_PEPPER + password).encode()).hexdigest()

def verify_password(password: str, stored_hash: str) -> bool:
    if stored_hash.startswith("$argon2"):
        return pwd_ctx.verify(password, stored_hash)
    # Legacy SHA-256 + pepper
    return hmac.compare_digest(_legacy_hash(password), stored_hash)

# ---------------------------------------------------------------------------
# API key encryption (Fernet, key derived from session token via HKDF)
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes as _crypto_hashes
    from cryptography.fernet import Fernet
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False
    logger.warning("cryptography package not available — API key will not be encrypted in transit.")

def _derive_fernet_key(session_token: str) -> bytes:
    hkdf = HKDF(
        algorithm=_crypto_hashes.SHA256(),
        length=32,
        salt=b"pan-copilot-apikey-v1",
        info=b"api-key-encryption",
    )
    return base64.urlsafe_b64encode(hkdf.derive(session_token.encode()))

def encrypt_api_key(api_key: str, session_token: str) -> Optional[str]:
    if not _CRYPTO_OK or not api_key or not session_token:
        return None
    try:
        return Fernet(_derive_fernet_key(session_token)).encrypt(api_key.encode()).decode()
    except Exception as e:
        logger.error(f"API key encryption failed: {e}")
        return None

# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------
def _real_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

limiter = Limiter(key_func=_real_ip)

# ---------------------------------------------------------------------------
# Lemon Squeezy variant map
# ---------------------------------------------------------------------------
LS_VARIANT_TIER = {
    # Keys are the numeric variant_id as sent in webhook payloads (str()'d).
    # The pro/max entries below are checkout-link UUIDs, NOT webhook variant_ids,
    # so they never match — pro/max resolve via the name-match instead.
    "1c4c4370-4557-4651-a684-fadaf1a44404": "pro",
    "0475eb28-6e6b-4f68-adcc-9de6045192d6": "max",
    "1680703": "local",
}

FREE_WEEKLY_LIMIT  = 10
PRO_MONTHLY_LIMIT  = 1_000
MAX_MONTHLY_LIMIT  = 2_500
OWNER_LIMIT        = 999_999
SESSION_TTL_DAYS   = 30
MAX_QUERY_WEIGHT   = 3  # max cost multiplier per query (e.g. free-tier large config pastes)

VALID_TIERS = frozenset({"free", "local", "pro", "max", "owner"})

TIER_LIMITS = {
    "free":  FREE_WEEKLY_LIMIT,
    "local": 0,                  # local-tier users never consume cloud quota
    "pro":   PRO_MONTHLY_LIMIT,
    "max":   MAX_MONTHLY_LIMIT,
    "owner": OWNER_LIMIT,
}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DB_PATH = Path(os.environ.get("DB_PATH", "/tmp/license_server.db"))

if str(DB_PATH).startswith("/tmp"):
    logger.warning(
        "DB_PATH is /tmp — data will be lost on every Render restart. "
        "Set DB_PATH to a persistent volume path in production."
    )

def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            TEXT PRIMARY KEY,
                email         TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                tier          TEXT NOT NULL DEFAULT 'free',
                seats_allowed INTEGER NOT NULL DEFAULT 1,
                created_at    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                user_id    TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS query_counts (
                user_id    TEXT NOT NULL,
                period_key TEXT NOT NULL,
                count      INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, period_key)
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_qc_user      ON query_counts(user_id);
        """)
        db.commit()

init_db()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def week_start() -> str:
    today = datetime.now(timezone.utc).date()
    return (today - timedelta(days=today.weekday())).isoformat()

def month_start() -> str:
    return datetime.now(timezone.utc).date().replace(day=1).isoformat()

def period_key(tier: str) -> str:
    return week_start() if tier == "free" else month_start()

def make_token() -> str:
    return secrets.token_urlsafe(40)

def get_user_by_token(token: str) -> Optional[sqlite3.Row]:
    with get_db() as db:
        return db.execute("""
            SELECT u.*, s.expires_at FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ? AND s.expires_at > ?
        """, (token, now_iso())).fetchone()

def get_query_count(user_id: str, tier: str) -> int:
    pk = period_key(tier)
    with get_db() as db:
        row = db.execute(
            "SELECT count FROM query_counts WHERE user_id = ? AND period_key = ?",
            (user_id, pk)
        ).fetchone()
    return row["count"] if row else 0

def query_limit_for(tier: str) -> int:
    return TIER_LIMITS.get(tier, FREE_WEEKLY_LIMIT)

def usage_response(user, queries_used: int = None, session_token: str = None) -> dict:
    tier    = user["tier"]
    limit   = query_limit_for(tier)
    used    = queries_used if queries_used is not None else get_query_count(user["id"], tier)
    period  = "weekly" if tier == "free" else "monthly"
    unlimited = (tier == "owner")

    # Local-tier accounts never get the Anthropic key. The app reads this
    # field as the signal that cloud chat is unavailable and shows the
    # "upgrade to Pro" lock in the provider settings panel.
    if tier == "local":
        encrypted_key = None
    else:
        encrypted_key = encrypt_api_key(ANTHROPIC_API_KEY, session_token) if session_token else None

    return {
        "email":             user["email"],
        "tier":              tier,
        "seats_allowed":     user["seats_allowed"],
        "period":            period if tier != "local" else None,
        "queries_used":      used  if tier != "local" else None,
        "queries_limit":     limit if tier != "local" else None,
        "queries_remaining": OWNER_LIMIT if unlimited else (max(0, limit - used) if tier != "local" else None),
        "unlimited":         unlimited,
        "weekly_used":       used  if tier == "free" else None,
        "weekly_limit":      limit if tier == "free" else None,
        "monthly_used":      used  if tier not in ("free", "local") else None,
        "monthly_limit":     limit if tier not in ("free", "local") else None,
        "anthropic_key":     encrypted_key,  # Fernet-encrypted, never plaintext
    }

# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------
app = FastAPI(title="PAN Copilot License Server", version="2.1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1",
        "http://localhost",
        "null",
    ],
    allow_origin_regex=r"http://(127\.0\.0\.1|localhost)(:\d+)?",
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type", "Authorization"],
)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class AuthRequest(BaseModel):
    email: str
    password: str

class TokenRequest(BaseModel):
    token: str
    weight: int = 1  # query cost multiplier: 1 = normal, 3 = free-tier large config (>8k chars)

class AdminTierRequest(BaseModel):
    email: str
    tier: str
    seats_allowed: int = 1

# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
@app.post("/auth/register")
@limiter.limit("3/hour")
def register(request: Request, req: AuthRequest):
    email = req.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email address.")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    user_id = str(uuid.uuid4())
    pw_hash = hash_password(req.password)
    ts      = now_iso()

    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO users (id, email, password_hash, tier, seats_allowed, created_at) "
                "VALUES (?, ?, ?, 'free', 1, ?)",
                (user_id, email, pw_hash, ts)
            )
            db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="An account with that email already exists.")

    token   = make_token()
    expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (token, user_id, ts, expires)
        )
        db.commit()

    new_user = {"id": user_id, "email": email, "tier": "free", "seats_allowed": 1}
    payload = usage_response(new_user, queries_used=0, session_token=token)
    payload["token"] = token
    return payload


@app.post("/auth/login")
@limiter.limit("5/minute")
def login(request: Request, req: AuthRequest):
    email = req.email.strip().lower()
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user or not verify_password(req.password, user["password_hash"]):
        logger.warning(f"Failed login attempt for: {email} from {_real_ip(request)}")
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    # Migrate legacy SHA-256 hash to argon2id on successful login
    if not user["password_hash"].startswith("$argon2"):
        new_hash = hash_password(req.password)
        with get_db() as db:
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
            db.commit()

    # Invalidate previous sessions for this user
    with get_db() as db:
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
        db.commit()

    token   = make_token()
    ts      = now_iso()
    expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (token, user["id"], ts, expires)
        )
        db.commit()

    payload = usage_response(user, session_token=token)
    payload["token"] = token
    return payload


@app.post("/auth/validate")
@limiter.limit("30/minute")
def validate_token(request: Request, req: TokenRequest):
    user = get_user_by_token(req.token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid. Please log in again.")
    payload = usage_response(user, session_token=req.token)
    payload["valid"] = True
    return payload

# ---------------------------------------------------------------------------
# Query counting
# ---------------------------------------------------------------------------
@app.post("/query/check")
@limiter.limit("120/minute")
def check_and_count(request: Request, req: TokenRequest):
    user = get_user_by_token(req.token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")

    tier   = user["tier"]
    limit  = query_limit_for(tier)
    pk     = period_key(tier)
    weight = max(1, min(req.weight, MAX_QUERY_WEIGHT))  # clamp to [1, MAX_QUERY_WEIGHT]

    if tier == "owner":
        return {
            "allowed": True, "tier": "owner", "period": "monthly",
            "queries_used": 0, "queries_limit": OWNER_LIMIT,
            "queries_remaining": OWNER_LIMIT, "unlimited": True,
        }

    # Local-tier accounts run chat on their own hardware — they should never
    # actually hit this endpoint (the app skips the quota call in local mode),
    # but if they do we answer "allowed, no count" so a misbehaving client
    # can't get stuck. Their requests cost ADK Cyber nothing on Anthropic.
    if tier == "local":
        return {
            "allowed": True, "tier": "local", "period": None,
            "queries_used": None, "queries_limit": None,
            "queries_remaining": None, "unlimited": False,
        }

    # Atomic check-and-increment to prevent TOCTOU race.
    # weight > 1 for free-tier large-config submissions (counts as 3 queries).
    with get_db() as db:
        # Ensure row exists
        db.execute("""
            INSERT INTO query_counts (user_id, period_key, count) VALUES (?, ?, 0)
            ON CONFLICT(user_id, period_key) DO NOTHING
        """, (user["id"], pk))
        db.commit()

        # Only increment if count + weight fits within the limit
        result = db.execute("""
            UPDATE query_counts SET count = count + ?
            WHERE user_id = ? AND period_key = ? AND count + ? <= ?
            RETURNING count
        """, (weight, user["id"], pk, weight, limit)).fetchone()
        db.commit()

    if result is None:
        # Limit already reached — fetch current count for the response
        with get_db() as db:
            row = db.execute(
                "SELECT count FROM query_counts WHERE user_id = ? AND period_key = ?",
                (user["id"], pk)
            ).fetchone()
        current = row["count"] if row else limit
        period_label = "week" if tier == "free" else "month"
        tier_label   = {"free": "Free", "pro": "Pro", "max": "MAX", "local": "Local"}.get(tier, tier.title())
        upgrade_msg  = (
            " Upgrade to Pro at adkcyber.com/pan-copilot.html for up to 1,000 queries/month."
            if tier == "free" else ""
        )
        return {
            "allowed": False, "tier": tier,
            "period": "weekly" if tier == "free" else "monthly",
            "queries_used": current, "queries_limit": limit, "queries_remaining": 0,
            "detail": f"{tier_label} tier limit reached ({current:,}/{limit:,} this {period_label}).{upgrade_msg}",
            "weekly_used": current if tier == "free" else None,
            "weekly_limit": limit  if tier == "free" else None,
        }

    new_count = result["count"]
    return {
        "allowed": True, "tier": tier,
        "period": "weekly" if tier == "free" else "monthly",
        "queries_used": new_count, "queries_limit": limit,
        "queries_remaining": limit - new_count,
        "weekly_used":  new_count if tier == "free" else None,
        "weekly_limit": limit     if tier == "free" else None,
        "monthly_used":  new_count if tier != "free" else None,
        "monthly_limit": limit     if tier != "free" else None,
    }

# ---------------------------------------------------------------------------
# Admin — token via Authorization: Bearer header
# ---------------------------------------------------------------------------
def _check_admin(authorization: str):
    token = authorization.replace("Bearer ", "").strip()
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden.")

@app.post("/admin/set-tier")
def set_tier(req: AdminTierRequest, authorization: str = Header(default="")):
    _check_admin(authorization)
    if req.tier not in VALID_TIERS:
        raise HTTPException(status_code=400, detail=f"tier must be one of: {', '.join(sorted(VALID_TIERS))}.")
    with get_db() as db:
        result = db.execute(
            "UPDATE users SET tier = ?, seats_allowed = ? WHERE email = ?",
            (req.tier, req.seats_allowed, req.email.strip().lower())
        )
        db.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="No user found with that email.")
    return {"ok": True, "email": req.email, "tier": req.tier, "seats_allowed": req.seats_allowed}


@app.get("/admin/users")
def list_users(authorization: str = Header(default="")):
    _check_admin(authorization)
    with get_db() as db:
        rows = db.execute(
            "SELECT id, email, tier, seats_allowed, created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]

# ---------------------------------------------------------------------------
# Lemon Squeezy webhook — signature always verified
# ---------------------------------------------------------------------------
@app.post("/webhook/lemonsqueezy")
async def lemonsqueezy_webhook(request: Request):
    body = await request.body()

    # Always verify — endpoint is disabled if secret not configured
    if not LS_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Webhook not configured.")

    sig      = request.headers.get("X-Signature", "")
    expected = hmac.new(LS_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        logger.warning("Webhook signature mismatch — possible forgery attempt.")
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    payload = json.loads(body)
    event   = payload.get("meta", {}).get("event_name", "")
    attrs   = payload.get("data", {}).get("attributes", {})

    email        = (attrs.get("user_email") or "").strip().lower()
    variant_name = (attrs.get("variant_name") or "").lower()
    product_name = (attrs.get("product_name") or "").lower()

    if "max" in variant_name or "max" in product_name:
        tier = "max"
    elif "pro" in variant_name or "pro" in product_name:
        tier = "pro"
    elif "local" in variant_name or "local" in product_name:
        tier = "local"
    else:
        tier = LS_VARIANT_TIER.get(str(attrs.get("variant_id", ""))) or "pro"

    if event in ("subscription_created", "subscription_updated", "subscription_resumed"):
        if not email:
            return {"ok": False, "reason": "no email in payload"}
        with get_db() as db:
            db.execute("UPDATE users SET tier = ? WHERE email = ?", (tier, email))
            db.commit()
        return {"ok": True, "event": event, "email": email, "tier": tier}

    elif event in ("subscription_cancelled", "subscription_expired", "subscription_paused"):
        if not email:
            return {"ok": False, "reason": "no email in payload"}
        with get_db() as db:
            db.execute("UPDATE users SET tier = 'free' WHERE email = ?", (email,))
            db.commit()
        return {"ok": True, "event": event, "email": email, "tier": "free"}

    return {"ok": True, "event": event, "handled": False}

# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "2.1.0",
        "limits": {
            "free_weekly": FREE_WEEKLY_LIMIT,
            "pro_monthly": PRO_MONTHLY_LIMIT,
            "max_monthly": MAX_MONTHLY_LIMIT,
        }
    }

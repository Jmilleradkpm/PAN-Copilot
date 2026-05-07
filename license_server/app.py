"""
PAN Copilot — License Server
============================
Lightweight FastAPI service deployed to Railway.

Responsibilities:
  1. User registration / login (email + password)
  2. Session token issuance and validation
  3. Query counting with tier-appropriate limits:
       Free  — 10 / week
       Pro   — 1,000 / month  (~$20 API cost ceiling)
       MAX   — 2,500 / month  (~$50 API cost ceiling)
  4. Returning ADK Cyber's Anthropic API key to authenticated users
  5. Tier management (free / pro / max)

Data that NEVER passes through here:
  - Firewall configs
  - PAN-OS CLI output
  - Any chat message content

The local app calls Anthropic directly using the key returned by /auth/login.
Configs go: user machine → Anthropic only.
This server only sees: email, hashed password, session tokens, query counts.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Config from environment variables (set these in Railway)
# ---------------------------------------------------------------------------

ANTHROPIC_API_KEY       = os.environ.get("ANTHROPIC_API_KEY", "")
SECRET_PEPPER           = os.environ.get("SECRET_PEPPER", "change-me-in-production")
ADMIN_TOKEN             = os.environ.get("ADMIN_TOKEN", "")
LS_WEBHOOK_SECRET       = os.environ.get("LS_WEBHOOK_SECRET", "")  # Lemon Squeezy webhook secret

# Map Lemon Squeezy variant UUIDs → tier strings
LS_VARIANT_TIER = {
    "1c4c4370-4557-4651-a684-fadaf1a44404": "pro",
    "0475eb28-6e6b-4f68-adcc-9de6045192d6": "max",
}

FREE_WEEKLY_LIMIT  = 10        # ~40 / month
PRO_MONTHLY_LIMIT  = 1_000     # API cost ≈ $20 at this volume
MAX_MONTHLY_LIMIT  = 2_500     # API cost ≈ $50 at this volume
OWNER_LIMIT        = 999_999   # Effectively unlimited

SESSION_TTL_DAYS = 30

TIER_LIMITS = {
    "free":  FREE_WEEKLY_LIMIT,
    "pro":   PRO_MONTHLY_LIMIT,
    "max":   MAX_MONTHLY_LIMIT,
    "owner": OWNER_LIMIT,
}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

DB_PATH = Path(os.environ.get("DB_PATH", "/tmp/license_server.db"))

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

            -- Reused for both weekly (free) and monthly (paid) counts.
            -- The `period_key` column stores:
            --   • free  → ISO date of the week's Monday  (e.g. 2025-06-02)
            --   • paid  → ISO date of month's first day  (e.g. 2025-06-01)
            CREATE TABLE IF NOT EXISTS query_counts (
                user_id    TEXT NOT NULL,
                period_key TEXT NOT NULL,
                count      INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, period_key)
            );

            -- Keep legacy column name working during migration
            CREATE TABLE IF NOT EXISTS query_counts_legacy (
                user_id    TEXT NOT NULL,
                week_start TEXT NOT NULL,
                count      INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, week_start)
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
    """ISO date of the most recent Monday (UTC)."""
    today = datetime.now(timezone.utc).date()
    monday = today - timedelta(days=today.weekday())
    return monday.isoformat()

def month_start() -> str:
    """ISO date of the first day of the current UTC month."""
    today = datetime.now(timezone.utc).date()
    return today.replace(day=1).isoformat()

def period_key(tier: str) -> str:
    """Return the appropriate counting period key for this tier."""
    if tier == "free":
        return week_start()
    return month_start()  # pro, max, owner all use monthly window

def hash_password(password: str) -> str:
    salted = SECRET_PEPPER + password
    return hashlib.sha256(salted.encode()).hexdigest()

def verify_password(password: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password), stored_hash)

def make_token() -> str:
    return secrets.token_urlsafe(40)

def get_user_by_token(token: str) -> Optional[sqlite3.Row]:
    now = now_iso()
    with get_db() as db:
        row = db.execute("""
            SELECT u.*, s.expires_at
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ? AND s.expires_at > ?
        """, (token, now)).fetchone()
    return row

def get_query_count(user_id: str, tier: str) -> int:
    """Current query count for the relevant period."""
    pk = period_key(tier)
    with get_db() as db:
        row = db.execute(
            "SELECT count FROM query_counts WHERE user_id = ? AND period_key = ?",
            (user_id, pk)
        ).fetchone()
    return row["count"] if row else 0

def query_limit_for(tier: str) -> int:
    return TIER_LIMITS.get(tier, FREE_WEEKLY_LIMIT)

def usage_response(user: sqlite3.Row, queries_used: int = None) -> dict:
    """Build the consistent usage payload returned by all auth/query endpoints."""
    tier = user["tier"]
    limit = query_limit_for(tier)
    used  = queries_used if queries_used is not None else get_query_count(user["id"], tier)
    period = "weekly" if tier == "free" else "monthly"

    unlimited = (tier == "owner")
    return {
        "email":         user["email"],
        "tier":          tier,
        "seats_allowed": user["seats_allowed"],
        "period":        period,
        "queries_used":  used,
        "queries_limit": limit,
        "queries_remaining": OWNER_LIMIT if unlimited else max(0, limit - used),
        "unlimited":     unlimited,
        # Legacy keys kept for older local-app versions
        "weekly_used":  used  if tier == "free" else None,
        "weekly_limit": limit if tier == "free" else None,
        "monthly_used":  used  if tier != "free" else None,
        "monthly_limit": limit if tier != "free" else None,
        "anthropic_key": ANTHROPIC_API_KEY if ANTHROPIC_API_KEY else None,
    }

# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(title="PAN Copilot License Server", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AuthRequest(BaseModel):
    email: str
    password: str

class TokenRequest(BaseModel):
    token: str

class AdminTierRequest(BaseModel):
    admin_token: str
    email: str
    tier: str
    seats_allowed: int = 1

# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.post("/auth/register")
def register(req: AuthRequest):
    email = req.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email address.")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    user_id = str(uuid.uuid4())
    pw_hash = hash_password(req.password)
    ts = now_iso()

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

    token = make_token()
    expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (token, user_id, ts, expires)
        )
        db.commit()

    # Fabricate a minimal Row-like object for usage_response
    class _User:
        def __getitem__(self, k):
            return {"id": user_id, "email": email, "tier": "free",
                    "seats_allowed": 1}[k]

    payload = usage_response(_User(), queries_used=0)
    payload["token"] = token
    return payload


@app.post("/auth/login")
def login(req: AuthRequest):
    email = req.email.strip().lower()
    with get_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    token = make_token()
    ts = now_iso()
    expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (token, user["id"], ts, expires)
        )
        db.commit()

    payload = usage_response(user)
    payload["token"] = token
    return payload


@app.post("/auth/validate")
def validate_token(req: TokenRequest):
    """Validate a session token and return current tier + query status."""
    user = get_user_by_token(req.token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid. Please log in again.")

    payload = usage_response(user)
    payload["valid"] = True
    return payload

# ---------------------------------------------------------------------------
# Query counting — called before every chat message
# ---------------------------------------------------------------------------

@app.post("/query/check")
def check_and_count(req: TokenRequest):
    """
    Check and increment the query counter.
    • Free  — weekly window, limit 10
    • Pro   — monthly window, limit 1,000
    • MAX   — monthly window, limit 2,500
    Returns {allowed, tier, period, queries_used, queries_limit, queries_remaining}.
    """
    user = get_user_by_token(req.token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")

    tier  = user["tier"]
    limit = query_limit_for(tier)
    pk    = period_key(tier)

    # Owner tier bypasses all query limits
    if tier == "owner":
        return {
            "allowed": True,
            "tier": "owner",
            "period": "monthly",
            "queries_used": 0,
            "queries_limit": OWNER_LIMIT,
            "queries_remaining": OWNER_LIMIT,
            "unlimited": True,
        }

    with get_db() as db:
        row = db.execute(
            "SELECT count FROM query_counts WHERE user_id = ? AND period_key = ?",
            (user["id"], pk)
        ).fetchone()
        current = row["count"] if row else 0

    if current >= limit:
        period_label = "week" if tier == "free" else "month"
        tier_label   = {"free": "Free", "pro": "Pro", "max": "MAX"}.get(tier, tier.title())
        upgrade_msg  = (
            " Upgrade to Pro at adkcyber.com/pan-copilot.html for up to 1,000 queries/month."
            if tier == "free" else ""
        )
        return {
            "allowed":            False,
            "tier":               tier,
            "period":             "weekly" if tier == "free" else "monthly",
            "queries_used":       current,
            "queries_limit":      limit,
            "queries_remaining":  0,
            "detail": (
                f"{tier_label} tier limit reached ({current:,}/{limit:,} this {period_label}).{upgrade_msg}"
            ),
            # Legacy
            "weekly_used":  current if tier == "free" else None,
            "weekly_limit": limit   if tier == "free" else None,
        }

    # Increment
    with get_db() as db:
        db.execute("""
            INSERT INTO query_counts (user_id, period_key, count) VALUES (?, ?, 1)
            ON CONFLICT(user_id, period_key) DO UPDATE SET count = count + 1
        """, (user["id"], pk))
        db.commit()

    new_count = current + 1
    return {
        "allowed":           True,
        "tier":              tier,
        "period":            "weekly" if tier == "free" else "monthly",
        "queries_used":      new_count,
        "queries_limit":     limit,
        "queries_remaining": limit - new_count,
        # Legacy
        "weekly_used":  new_count if tier == "free" else None,
        "weekly_limit": limit     if tier == "free" else None,
        "monthly_used":  new_count if tier != "free" else None,
        "monthly_limit": limit     if tier != "free" else None,
    }

# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.post("/admin/set-tier")
def set_tier(req: AdminTierRequest):
    if not ADMIN_TOKEN or req.admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden.")
    if req.tier not in ("free", "pro", "max", "owner"):
        raise HTTPException(status_code=400, detail="tier must be free, pro, max, or owner.")

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
def list_users(admin_token: str = ""):
    if not ADMIN_TOKEN or admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden.")
    with get_db() as db:
        rows = db.execute(
            "SELECT id, email, tier, seats_allowed, created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]

# ---------------------------------------------------------------------------
# Lemon Squeezy webhook
# ---------------------------------------------------------------------------

@app.post("/webhook/lemonsqueezy")
async def lemonsqueezy_webhook(request: Request):
    """
    Receives Lemon Squeezy subscription events and updates user tiers.
    Verifies HMAC-SHA256 signature using LS_WEBHOOK_SECRET.
    """
    body = await request.body()

    # Verify signature
    if LS_WEBHOOK_SECRET:
        sig = request.headers.get("X-Signature", "")
        expected = hmac.new(
            LS_WEBHOOK_SECRET.encode(), body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, sig):
            raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    import json
    payload = json.loads(body)
    event   = payload.get("meta", {}).get("event_name", "")
    data    = payload.get("data", {})
    attrs   = data.get("attributes", {})

    # Extract email and determine tier
    email         = (attrs.get("user_email") or "").strip().lower()
    variant_name  = (attrs.get("variant_name") or "").lower()
    product_name  = (attrs.get("product_name") or "").lower()

    # Determine tier from variant/product name (most reliable)
    if "max" in variant_name or "max" in product_name:
        tier = "max"
    elif "pro" in variant_name or "pro" in product_name:
        tier = "pro"
    else:
        # Fallback: try integer variant_id map (update these from LS dashboard if needed)
        tier = LS_VARIANT_TIER.get(str(attrs.get("variant_id", ""))) or "pro"

    if event in ("subscription_created", "subscription_updated", "subscription_resumed"):
        if not email:
            return {"ok": False, "reason": "no email in payload"}
        new_tier = tier if tier else "pro"  # safe default
        with get_db() as db:
            db.execute(
                "UPDATE users SET tier = ? WHERE email = ?",
                (new_tier, email)
            )
            db.commit()
        return {"ok": True, "event": event, "email": email, "tier": new_tier}

    elif event in ("subscription_cancelled", "subscription_expired", "subscription_paused"):
        if not email:
            return {"ok": False, "reason": "no email in payload"}
        with get_db() as db:
            db.execute(
                "UPDATE users SET tier = 'free' WHERE email = ?",
                (email,)
            )
            db.commit()
        return {"ok": True, "event": event, "email": email, "tier": "free"}

    # Ignore all other events (order_created, etc.)
    return {"ok": True, "event": event, "handled": False}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "2.0.0",
        "limits": {
            "free_weekly":  FREE_WEEKLY_LIMIT,
            "pro_monthly":  PRO_MONTHLY_LIMIT,
            "max_monthly":  MAX_MONTHLY_LIMIT,
        }
    }

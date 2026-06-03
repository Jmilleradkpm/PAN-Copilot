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

import asyncio
import base64
import hmac
import json
import logging
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
from typing import Optional, List
from xml.etree import ElementTree as ET

# ---------------------------------------------------------------------------
# App version — replaced by CI at build time
# ---------------------------------------------------------------------------
APP_VERSION = "0.0.0"
if APP_VERSION == "0.0.0":
    logging.warning(
        "APP_VERSION is 0.0.0 — CI version substitution may not have run. "
        "The update banner may fire incorrectly in local dev builds."
    )

import anthropic
import httpx
import io
import zipfile

from fastapi import FastAPI, HTTPException, UploadFile, File, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse, Response
from pydantic import BaseModel, field_validator

logger = logging.getLogger("pan_copilot")

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
# Cloud and local prompt variants. The encrypted (.enc) form is what production
# exes ship; the plain .md form is what local dev installs read. The decrypt
# helper below tries .enc first and falls back to .md, so both paths work.
SYSTEM_PROMPT_CLOUD_ENC = _base() / "PAN_Copilot_Master_System_Prompt.md.enc"
SYSTEM_PROMPT_LOCAL_MD  = _base() / "PAN_Copilot_Master_System_Prompt_Local.md"
SYSTEM_PROMPT_LOCAL_ENC = _base() / "PAN_Copilot_Master_System_Prompt_Local.md.enc"
KB_DIR             = _base() / "kb"

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
# Settings — chat provider preferences (cloud vs local LLM)
# ---------------------------------------------------------------------------
# These live in a separate settings.json so they're independent of the
# session-token file and survive a logout. Defaults: cloud provider on,
# Ollama as the local LLM template (user must change to fit their setup).

SETTINGS_FILE = CONFIG_DIR / "settings.json"

_VALID_PROVIDERS = {"cloud", "local"}

_DEFAULT_SETTINGS = {
    "chat_provider":  "cloud",
    "local_base_url": "http://localhost:11434/v1",   # Ollama default
    "local_model":    "qwen2.5:14b",                  # placeholder; user picks
    "local_api_key":  "",                             # most local servers need none
    "local_history_turns": 40,                        # messages of history sent to a local model (≈20 exchanges)
    "local_context_tokens": 32768,                    # assumed context window for budget warnings
    "local_truncate_config": True,                    # auto-truncate huge config pastes in local mode
    "local_max_tokens": 8192,                         # max completion tokens sent to local server
    "local_temperature": 0.2,                         # generation temperature (OpenAI-compatible)
    "local_supports_vision": False,                   # enable only if the loaded model supports images
}


def _normalize_settings(data: dict) -> dict:
    """Clamp local LLM settings to sane ranges."""
    cleaned = {k: data.get(k, v) for k, v in _DEFAULT_SETTINGS.items()}
    if cleaned["chat_provider"] not in _VALID_PROVIDERS:
        cleaned["chat_provider"] = "cloud"
    cleaned["local_history_turns"] = max(2, min(int(cleaned.get("local_history_turns") or 40), 400))
    cleaned["local_context_tokens"] = max(4096, min(int(cleaned.get("local_context_tokens") or 32768), 200000))
    cleaned["local_max_tokens"] = max(256, min(int(cleaned.get("local_max_tokens") or 8192), 131072))
    temp = float(cleaned.get("local_temperature") if cleaned.get("local_temperature") is not None else 0.2)
    cleaned["local_temperature"] = round(max(0.0, min(temp, 2.0)), 2)
    cleaned["local_truncate_config"] = bool(cleaned.get("local_truncate_config", True))
    cleaned["local_supports_vision"] = bool(cleaned.get("local_supports_vision", False))
    return cleaned


def load_settings() -> dict:
    """Return current settings dict, filling in any missing keys with defaults."""
    out = dict(_DEFAULT_SETTINGS)
    if SETTINGS_FILE.exists():
        try:
            raw = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for k in _DEFAULT_SETTINGS:
                    if k in raw and raw[k] is not None:
                        out[k] = raw[k]
        except Exception:
            pass
    if out.get("chat_provider") not in _VALID_PROVIDERS:
        out["chat_provider"] = "cloud"
    return _normalize_settings(out)


def save_settings(data: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cleaned = _normalize_settings(data)
    SETTINGS_FILE.write_text(json.dumps(cleaned, indent=2), encoding="utf-8")
    try:
        import stat
        SETTINGS_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


class SettingsPayload(BaseModel):
    chat_provider:         Optional[str] = None
    local_base_url:        Optional[str] = None
    local_model:           Optional[str] = None
    local_api_key:         Optional[str] = None
    local_history_turns:   Optional[int] = None
    local_context_tokens:  Optional[int] = None
    local_truncate_config: Optional[bool] = None
    local_max_tokens:      Optional[int] = None
    local_temperature:     Optional[float] = None
    local_supports_vision: Optional[bool] = None


class LocalLLMTestRequest(BaseModel):
    base_url: str
    model:    str
    api_key:  Optional[str] = None


class LocalContextEstimateRequest(BaseModel):
    config_text: Optional[str] = ""
    message: Optional[str] = ""
    conversation_id: Optional[str] = None


_LOCAL_CONFIG_TRUNCATION_NOTE = (
    "\n\n[... config truncated for local context budget — paste a smaller section "
    "for full analysis ...]\n\n"
)


def _estimate_tokens(text: str) -> int:
    return max(0, len(text or "") // 4)


def _history_char_count(conversation_id: Optional[str], limit: int) -> int:
    if not conversation_id:
        return 0
    hist = load_conversation_history(conversation_id, limit=limit)
    return sum(len(str(t.get("content") or "")) for t in hist)


def estimate_local_context_usage(
    *,
    config_text: str = "",
    message: str = "",
    conversation_id: Optional[str] = None,
    settings: Optional[dict] = None,
) -> dict:
    """Rough token budget for local mode (chars/4 heuristic)."""
    st = settings or load_settings()
    context_limit = int(st.get("local_context_tokens") or 32768)
    hist_limit = int(st.get("local_history_turns") or _MAX_HISTORY_TURNS)
    system_tokens = _estimate_tokens(SYSTEM_PROMPT_LOCAL)
    message_tokens = _estimate_tokens(message)
    config_tokens = _estimate_tokens(config_text)
    history_tokens = _estimate_tokens(
        "x" * _history_char_count(conversation_id, hist_limit)
    )
    reserve_output = int(st.get("local_max_tokens") or 8192)
    overhead = 200
    estimated_input = system_tokens + message_tokens + config_tokens + history_tokens + overhead
    total_estimated = estimated_input + reserve_output
    warn_threshold = int(context_limit * 0.7)
    return {
        "context_limit": context_limit,
        "estimated_input_tokens": estimated_input,
        "estimated_total_tokens": total_estimated,
        "reserve_output_tokens": reserve_output,
        "breakdown": {
            "system": system_tokens,
            "message": message_tokens,
            "config": config_tokens,
            "history": history_tokens,
            "overhead": overhead,
        },
        "warn": total_estimated >= warn_threshold,
        "over_budget": total_estimated > context_limit,
    }


def _truncate_config_for_local(
    config_text: str,
    *,
    settings: dict,
    message: str,
    conversation_id: Optional[str],
) -> tuple[str, bool]:
    if not config_text or not config_text.strip():
        return config_text, False
    if not settings.get("local_truncate_config", True):
        return config_text, False

    budget = estimate_local_context_usage(
        config_text=config_text,
        message=message,
        conversation_id=conversation_id,
        settings=settings,
    )
    if not budget["over_budget"]:
        return config_text, False

    context_limit = budget["context_limit"]
    reserve = budget["reserve_output_tokens"]
    hist_limit = int(settings.get("local_history_turns") or _MAX_HISTORY_TURNS)
    fixed = (
        budget["breakdown"]["system"]
        + budget["breakdown"]["message"]
        + budget["breakdown"]["history"]
        + budget["breakdown"]["overhead"]
        + reserve
    )
    config_budget_tokens = max(0, context_limit - fixed)
    max_chars = config_budget_tokens * 4
    if len(config_text) <= max_chars:
        return config_text, False
    if max_chars < 500:
        head = max_chars // 2
        tail = max_chars - head
        truncated = (
            config_text[:head]
            + _LOCAL_CONFIG_TRUNCATION_NOTE
            + config_text[-tail:]
        )
    else:
        truncated = config_text[:max_chars] + _LOCAL_CONFIG_TRUNCATION_NOTE
    return truncated, True

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
            -- Cached Palo Alto Networks security advisories. We populate this
            -- from https://security.paloaltonetworks.com/rss.xml once per hour.
            -- dismissed_at NULL means the row should appear in the alert banner;
            -- a non-NULL value means either the user dismissed it OR the row was
            -- "auto-dismissed" on first launch (existing items at install time
            -- are not shown — only newly published advisories trigger alerts).
            CREATE TABLE IF NOT EXISTS advisories (
                cve_id        TEXT PRIMARY KEY,
                title         TEXT NOT NULL,
                link          TEXT NOT NULL,
                severity      TEXT NOT NULL,
                pub_date      TEXT,
                seen_at       TEXT NOT NULL,
                dismissed_at  TEXT
            );
        """)
        db.commit()

init_db()


# Strip the "💭 **Thinking**\n\n…\n\n---\n\n" prefix from any assistant rows
# that were saved before the persist-side fix landed. Local reasoning models
# stream their chain-of-thought wrapped in that marker; if it stays in the DB
# and is replayed on the next turn, some GGUF chat templates fail to render
# the assistant message and the server returns an empty stream — making old
# conversations appear to break after one continuation. Idempotent: the LIKE
# filter restricts work to candidate rows and the regex is anchored to the
# row start, so reruns are no-ops.
_THINKING_PREFIX_RE = re.compile(
    r"^💭 \*\*Thinking\*\*\n\n.*?\n\n---\n\n",
    flags=re.DOTALL,
)

def _strip_thinking_from_existing_rows():
    with get_db() as db:
        rows = db.execute(
            "SELECT id, content FROM messages "
            "WHERE role = 'assistant' AND content LIKE '💭 **Thinking**%'"
        ).fetchall()
        for row in rows:
            cleaned = _THINKING_PREFIX_RE.sub("", row["content"], count=1)
            if cleaned != row["content"]:
                db.execute(
                    "UPDATE messages SET content = ? WHERE id = ?",
                    (cleaned, row["id"]),
                )
        db.commit()

_strip_thinking_from_existing_rows()

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

def _load_prompt_aes_key() -> Optional[bytes]:
    """Load the AES-256-GCM key used to decrypt the bundled prompt files.

    The key lives in a private module local/_prompt_key.py that is gitignored
    and written by CI from the PAN_COPILOT_PROMPT_AES_KEY GitHub Secret. Local
    dev installs that haven't run the encrypt step won't have this file —
    in that case we return None and the loader falls back to plaintext .md.
    """
    try:
        import importlib
        mod = importlib.import_module("_prompt_key")
    except Exception:
        return None
    key_b64 = getattr(mod, "PROMPT_KEY_B64", None)
    if not key_b64:
        return None
    try:
        key = base64.b64decode(key_b64)
    except Exception:
        return None
    if len(key) != 32:
        logger.warning("PROMPT_KEY_B64 must decode to 32 bytes — got %d", len(key))
        return None
    return key


def _decrypt_prompt_file(enc_path: Path, key: bytes) -> Optional[str]:
    """Decrypt a .enc file produced by the CI encrypt step.

    File format: [12-byte nonce][ciphertext+tag]. AES-256-GCM.
    Returns the plaintext string, or None if decryption fails.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        blob = enc_path.read_bytes()
        if len(blob) < 13:
            return None
        nonce, ct = blob[:12], blob[12:]
        return AESGCM(key).decrypt(nonce, ct, associated_data=None).decode("utf-8")
    except Exception as e:
        logger.warning("Failed to decrypt %s: %s", enc_path.name, e)
        return None


def _extract_prompt_body(raw: str) -> str:
    """Strip the markdown header / 'COPY BELOW' marker so only the live prompt
    body is returned. Same logic the original load_system_prompt used."""
    marker = "## SYSTEM PROMPT (COPY EVERYTHING BELOW THIS LINE)"
    if marker in raw:
        return re.sub(r"^[\s\-]+", "", raw.split(marker, 1)[1]).strip()
    return raw.strip()


_FALLBACK_PROMPT = (
    "You are ADK Cyber AI, an expert AI assistant for Palo Alto Networks engineers. "
    "You have deep knowledge of the full PAN portfolio including PAN-OS 8.x through 11.x, "
    "Panorama, Cortex XDR, XSIAM, XSOAR, Prisma Access, Prisma Cloud, Prisma SD-WAN, "
    "GlobalProtect, WildFire, Advanced Threat Prevention, DNS Security, URL Filtering, "
    "Strata Cloud Manager, and AI Runtime Security. "
    "Be direct, precise, and practical. When the user pastes config or CLI output, "
    "analyze it carefully before answering."
)


def load_system_prompt(variant: str = "cloud") -> str:
    """Load the master system prompt.

    variant="cloud" → the full 17 KB prompt used with Anthropic models.
    variant="local" → a compressed prompt sized for local LLM context budgets.

    Resolution order for each variant:
      1. <name>.md.enc decrypted with the AES key from _prompt_key.py
      2. <name>.md plaintext (local dev fallback)
      3. A short inline fallback string
    """
    if variant == "local":
        enc_path = SYSTEM_PROMPT_LOCAL_ENC
        md_path  = SYSTEM_PROMPT_LOCAL_MD
    else:
        enc_path = SYSTEM_PROMPT_CLOUD_ENC
        md_path  = SYSTEM_PROMPT_PATH

    key = _load_prompt_aes_key()
    if key and enc_path.exists():
        plaintext = _decrypt_prompt_file(enc_path, key)
        if plaintext:
            return _extract_prompt_body(plaintext)
        # decrypt failed — fall through to plaintext fallback below

    if md_path.exists():
        return _extract_prompt_body(md_path.read_text(encoding="utf-8"))

    return _FALLBACK_PROMPT

_RESPONSE_STYLE_ADDENDUM = """

## Response Length and Style — Non-Negotiable Rules

Read the user's question carefully and match response length to the complexity of what was actually asked.

- **Conceptual / "why" questions** (e.g. "why would I use X instead of Y?"): answer in 2–5 sentences. Explain the core reason. Stop. Do not add implementation steps, decision trees, comparison tables, or "bottom line" sections unless the user asks for them.
- **"How do I" / implementation questions**: provide the relevant steps or CLI. Do not pad with conceptual background the user did not request.
- **Short clarification questions** ("what does X mean?"): one short paragraph maximum.
- **Never volunteer information beyond what was asked.** If the user wants more depth they will ask a follow-up.
- Do not add headers, tables, bullet-point comparisons, or decision trees to a simple conceptual question.
- Default to the shortest accurate answer. Expand only when the question is explicitly broad.
"""


SYSTEM_PROMPT       = load_system_prompt("cloud") + _RESPONSE_STYLE_ADDENDUM
SYSTEM_PROMPT_LOCAL = load_system_prompt("local") + _RESPONSE_STYLE_ADDENDUM

# ---------------------------------------------------------------------------
# KB index — zero-token local responses
#
# When a user's question matches a KB article's trigger phrases, the full
# article is streamed back directly without any Anthropic API call.
# This saves the user's query quota AND eliminates API latency entirely.
#
# To add a new KB article:
#   1. Drop a .md file into local/kb/
#   2. Add an entry below in _KB_TRIGGER_MAP keyed by filename
#   3. List trigger phrases (any one match → serve this article)
# ---------------------------------------------------------------------------

_KB_TRIGGER_MAP: dict = {
    "gp_always_prelogon.md": {
        "kb_id": "KB-GP-PRELOGON-001",
        "title": "GlobalProtect Always Pre-Logon (Always On) — Complete Setup Guide",
        "triggers": [
            "pre-logon",
            "pre logon",
            "prelogon",
            "always pre-logon",
            "always pre logon",
            "gp pre-logon",
            "gp pre logon",
            "globalprotect pre-logon",
            "globalprotect pre logon",
            "globalprotect always on",
            "always-on vpn",
            "always on vpn",
            "machine cert globalprotect",
            "globalprotect machine cert",
            "machine certificate globalprotect",
            "globalprotect machine certificate",
            "kb-gp-prelogon",
            "kb-gp-prelogon-001",
        ],
    },
    "pan_decryption_troubleshooting.md": {
        "kb_id": "KB-PAN-DEC-001",
        "title": "SSL/TLS Decryption Troubleshooting on Palo Alto Networks NGFW",
        "triggers": [
            # Decryption modes
            "ssl decryption",
            "tls decryption",
            "ssl/tls decryption",
            "ssl forward proxy",
            "forward proxy",
            "ssl inbound inspection",
            "inbound inspection",
            "ssh proxy",
            # Policy/profile terminology
            "decryption profile",
            "decrypt rule",
            "decryption policy",
            "decryption rule",
            "no-decrypt",
            "no decrypt",
            "nodecrypt",
            "ssl exclusion",
            "decryption exclusion",
            # Trust & cert issues
            "forward trust",
            "forward trust ca",
            "forward untrust",
            "incomplete chain",
            "certificate chain",
            "cert chain",
            # Failure modes
            "decryption failure",
            "decryption log",
            "decryption troubleshoot",
            "decrypt troubleshoot",
            "decrypt broken",
            "decryption broken",
            "untrusted issuer",
            "unsupported cipher",
            "unsupported version",
            "sni mismatch",
            # Pinning & mTLS
            "cert pinning",
            "certificate pinning",
            "pinned cert",
            "mutual tls",
            "mtls",
            "client authentication required",
            # QUIC
            "block quic",
            "quic bypass",
            "quic decrypt",
            "quic http",
            "http/3",
            "http3",
            # OCSP/CRL
            "ocsp firewall",
            "ocsp decryption",
            "crl firewall",
            "unknown certificate status",
            # ECH / Encrypted ClientHello (v2.0)
            "ech",
            "encrypted clienthello",
            "encrypted client hello",
            "esni",
            # Half-loading websites (v2.0)
            "half-loading",
            "half loading",
            "half load",
            "partial load",
            "website half",
            "site half loads",
            # Resource exhaustion (v2.0)
            "resource exhaustion",
            "decryption resource",
            "proxy_no_resource",
            "decrypt resource",
            # DNS-over-HTTPS / DNS-over-TLS / SVCB controls (v2.0)
            "svcb",
            "https record",
            "doh firewall",
            "dot firewall",
            "dns over https firewall",
            "dns over tls firewall",
            # Wireshark / packet capture (v2.0)
            "wireshark tls",
            "tls alert",
            "tls alert code",
            "packet capture decrypt",
            # HAR file diagnostics (v2.0)
            "har file",
            "har export",
            "devtools network",
            # Escalation / TAC (v2.0)
            "tac case decryption",
            "escalation checklist",
            "decryption escalation",
            # Baseline posture / what not to do (v2.0)
            "decryption best practice",
            "decrypt best practice",
            "disable decryption",
            # Direct KB ID references
            "kb-pan-dec",
            "kb-pan-dec-001",
        ],
    },
    "pan_nat_troubleshooting.md": {
        "kb_id": "KB-PAN-NAT-001",
        "title": "NAT on Palo Alto Networks NGFW — VPN, U-Turn, Policy Zones, and Destination NAT",
        "triggers": [
            # Core NAT terminology
            "nat policy",
            "nat rule",
            "nat rules",
            "pan-os nat",
            "panos nat",
            "nat configuration",
            "nat troubleshoot",
            "nat not working",
            "nat broken",
            "nat issue",
            "nat problem",
            "nat mismatch",
            # Source / destination NAT types
            "source nat",
            "destination nat",
            "dnat",
            "snat",
            "static nat",
            "bidirectional nat",
            "dynamic ip and port",
            "dipp",
            "dipp pool",
            "dipp exhaustion",
            "nat pool exhaustion",
            "port exhaustion nat",
            "nat_dynamic_port_xlat_failed",
            "nat oversubscription",
            "show running ippool",
            # No-NAT / exemptions
            "no-nat",
            "no nat",
            "nat exemption",
            "nat bypass",
            "nat exclusion",
            # VPN + NAT interaction
            "vpn nat",
            "nat vpn",
            "vpn no-nat",
            "vpn no nat",
            "nat across vpn",
            "site-to-site nat",
            "ipsec nat",
            "vpn source nat",
            "vpn traffic nat",
            "nat blocking vpn",
            "nat tunnel",
            "tunnel nat",
            "internet nat vpn",
            # U-turn / hairpin NAT
            "u-turn nat",
            "u turn nat",
            "uturn nat",
            "hairpin nat",
            "hairpin",
            "internal server public ip",
            "internal server public fqdn",
            "access server by public ip",
            "loopback nat",
            "internal to public fqdn",
            # Inbound DNAT / DMZ
            "inbound nat",
            "inbound dnat",
            "dmz nat",
            "dmz server nat",
            "nat to dmz",
            "public to dmz",
            "destination nat dmz",
            "nat zone dmz",
            # Pre/post NAT zone confusion
            "pre-nat zone",
            "post-nat zone",
            "pre nat zone",
            "post nat zone",
            "pre-nat",
            "post-nat",
            "nat zone",
            "nat destination zone",
            "untrust to dmz nat",
            "nat security rule zone",
            # Outbound NAT
            "outbound nat",
            "internet nat",
            "egress nat",
            # HA + NAT
            "active active nat",
            "active/active nat",
            "ha nat",
            "nat ha",
            "nat failover",
            "nat binding",
            "device binding nat",
            "asymmetric nat",
            "ha nat asymmetric",
            # NAT CLI commands
            "test nat-policy-match",
            "nat-policy-match",
            "nat policy match",
            "show running nat-policy",
            "show running ippool",
            # Proxy ARP
            "proxy arp nat",
            "nat proxy arp",
            # DNS + NAT
            "dns rewrite nat",
            "nat dns rewrite",
            "split dns nat",
            "dns nat",
            # PCNSE NAT scenarios
            "pcnse nat",
            "nat pcnse",
            # Direct KB ID references
            "kb-pan-nat",
            "kb-pan-nat-001",
        ],
    },
    "pan_appid_unknown_troubleshooting.md": {
        "kb_id": "KB-PAN-APPID-001",
        "title": "App-ID unknown-tcp and unknown-udp — Causes, Fixes, and the Custom App-ID Lifecycle",
        "triggers": [
            # Core unknown App-ID terms
            "unknown-tcp",
            "unknown-udp",
            "unknown tcp",
            "unknown udp",
            "unknown app",
            "unknown application",
            "app-id unknown",
            "appid unknown",
            "app id unknown",
            # App-ID general
            "app-id",
            "appid",
            "app id classification",
            "app-id classification",
            "app-id engine",
            "appid engine",
            "app-id lifecycle",
            "app-id not matching",
            "app-id mismatch",
            "app-id broken",
            "app-id issue",
            "app-id problem",
            # Custom App-ID / signatures
            "custom app-id",
            "custom appid",
            "custom app id",
            "custom application",
            "custom application signature",
            "app-id signature",
            "appid signature",
            "custom signature",
            "write app-id",
            "create app-id",
            "build app-id",
            "app-id pattern",
            # Signature contexts
            "unknown-req",
            "unknown-rsp",
            "http-req-headers",
            "ssl-cert-subject",
            "ssl-cert-issuer",
            "dns-req-header",
            "packet-payload context",
            # Application override
            "application override",
            "app override",
            "appid override",
            "override policy",
            "app-id override",
            "policy override application",
            # PAN-303959 defect
            "pan-303959",
            "pan303959",
            "appid resource exhaustion",
            "app-id resource exhaustion",
            "app-id resource",
            "appid resource",
            "app resource alloc",
            "app_resource_alloc_fail",
            # Non-SYN / asymmetric
            "non-syn-tcp",
            "non syn tcp",
            "nonsyntcp",
            "asymmetric app-id",
            "asymmetric appid",
            # Incomplete sessions
            "incomplete tcp",
            "incomplete session",
            "incomplete app",
            "insufficient-data",
            "insufficient data app",
            # Policy logic traps
            "ssl web-browsing trap",
            "app-id dependency",
            "appid dependency",
            "application dependency",
            "implicit dependency",
            "explicit dependency",
            "app-id update safeguard",
            "appid update safeguard",
            # Applipedia / content
            "applipedia",
            "app-id database",
            "appid database",
            "content update app-id",
            "app-id content update",
            "content update appid",
            # App-ID Cloud Engine
            "app-id cloud engine",
            "appid cloud engine",
            "cloud app-id",
            # CLI commands
            "test application-identification",
            "application-identification pcap",
            "test appid pcap",
            "show app-id-engine",
            "app-id-engine status",
            "show application type custom",
            "show running application-override",
            "debug app-id",
            # Monitoring / ACC
            "acc unknown-tcp",
            "acc unknown tcp",
            "acc unknown application",
            "monitor unknown app",
            # PCNSE App-ID questions
            "pcnse app-id",
            "pcnse appid",
            "pcnse unknown-tcp",
            "pcnse unknown tcp",
            # Direct KB ID references
            "kb-pan-appid",
            "kb-pan-appid-001",
        ],
    },
    "pan_ha_failover_troubleshooting.md": {
        "kb_id": "KB-PAN-HA-001",
        "title": "HA Failover, Stuck-in-Initial-State, and HA Link Design on PAN-OS NGFW",
        "triggers": [
            # HA general
            "high availability",
            "high-availability",
            "failover",
            "firewall failover",
            "pan failover",
            "ha failover",
            "ha pair",
            "ha cluster",
            "ha setup",
            "ha config",
            "ha configuration",
            "ha issue",
            "ha problem",
            "ha troubleshoot",
            "ha not working",
            "ha broken",
            "ha down",
            # Stuck in initial
            "stuck in initial",
            "stuck-in-initial",
            "ha initial state",
            "initial state ha",
            "firewall initial state",
            "waiting for state synchronization",
            "state synchronization completion",
            "ha stuck",
            "stuck initial",
            "peer stuck",
            "passive stuck",
            # HA states
            "ha state",
            "ha states",
            "ha passive",
            "ha active",
            "ha suspended",
            "ha non-functional",
            "non-functional ha",
            "ha non functional",
            "non functional ha",
            "ha tentative",
            "tentative state",
            "tentative ha",
            "ha functional",
            "request ha state",
            "request high-availability state",
            # Split-brain
            "split-brain",
            "split brain",
            "both active ha",
            "both firewalls active",
            "dual active ha",
            "ha split brain",
            "two active firewalls",
            # HA links
            "ha1",
            "ha2",
            "ha3",
            "ha1 link",
            "ha2 link",
            "ha3 link",
            "ha1-backup",
            "ha2-backup",
            "ha1 backup",
            "ha2 backup",
            "ha1 failure",
            "ha2 failure",
            "ha1 down",
            "ha2 down",
            "ha link down",
            "ha link failure",
            "ha link flapping",
            "ha flapping",
            "ha failover loop",
            "ha link",
            "ha control link",
            # HSCI
            "hsci",
            "high speed chassis interconnect",
            "hsci link",
            "hsci failure",
            "hsci down",
            "hsci-a",
            "hsci-b",
            "chassis ha",
            "pa-7000 ha",
            "pa-7500 ha",
            "pa-5400 ha",
            "pa-5450 ha",
            # Session synchronization
            "session synchronization",
            "session sync",
            "ha session sync",
            "session sync ha",
            "ha2 session sync",
            "session synchronization ha",
            "sync sessions ha",
            "ha sync",
            "state synchronization",
            "show high-availability state-synchronization",
            "ha2 keep-alive",
            "ha2 keepalive",
            "ha2 keep alive",
            # Plugin mismatch
            "plugin mismatch ha",
            "ha plugin mismatch",
            "plugin mismatch",
            "plugin version ha",
            "ha plugin version",
            "incompatible plugin",
            "plugin incompatible ha",
            "show plugins installed",
            # Path monitoring
            "path monitoring ha",
            "ha path monitoring",
            "path monitoring misconfiguration",
            "path monitoring failover",
            "path monitor ha",
            "ha path monitor",
            "path monitoring cascade",
            "ha flap path monitoring",
            "path monitoring 8.8.8.8",
            "test high-availability path-monitoring",
            # Preemption
            "ha preemption",
            "preemption ha",
            "ha preempt",
            "preempt ha",
            "preemption hold time",
            "preemption misconfiguration",
            "ha election",
            "ha priority",
            "ha preemptive",
            # Active/Passive
            "active passive ha",
            "active/passive ha",
            "active passive firewall",
            "ha active passive",
            # Active/Active
            "active active ha",
            "active/active ha",
            "ha active active",
            "floating ip ha",
            "ha floating ip",
            "ha3 forwarding",
            "session owner ha",
            "device binding ha",
            # HA upgrade
            "ha upgrade",
            "upgrade ha pair",
            "upgrade ha",
            "ha upgrade sequence",
            "passive first upgrade",
            "upgrade passive first",
            "ha upgrade order",
            "ha maintenance",
            "ha upgrade runbook",
            # HA agent / logs
            "ha agent",
            "ha_agent.log",
            "ha agent log",
            "show high-availability",
            "show high-availability state",
            "show high-availability all",
            "show high-availability transitions",
            "show high-availability link-monitoring",
            "show high-availability interface ha2",
            "show interface ha1",
            "show interface ha2",
            # Timers
            "ha dead interval",
            "dead interval ha",
            "ha hello interval",
            "hello interval ha",
            "promotion hold time",
            "ha timers",
            "ha2 timing",
            # VM-Series HA
            "vm-series ha",
            "vseries ha",
            "vm ha",
            # Panorama + HA
            "panorama ha",
            "ha panorama",
            "panorama managed ha",
            # PCNSE HA
            "pcnse ha",
            "ha pcnse",
            "pcnse high availability",
            "pcnse failover",
            # Direct KB ID references
            "kb-pan-ha",
            "kb-pan-ha-001",
        ],
    },
    "pan_userid_troubleshooting.md": {
        "kb_id": "KB-SEC-UID-001",
        "title": "PAN-OS User-ID — Users Not Appearing in Traffic Logs",
        "triggers": [
            # User-ID general
            "user-id",
            "userid",
            "user id",
            "pan-os user-id",
            "panos user-id",
            "user identification",
            "user id not working",
            "user-id broken",
            "user-id issue",
            "user-id problem",
            "user-id troubleshoot",
            "user-id config",
            "user-id configuration",
            # Source user symptoms
            "source user blank",
            "source user empty",
            "source user unknown",
            "username not showing",
            "username missing",
            "username blank",
            "username not in logs",
            "users not in logs",
            "users not appearing",
            "user not appearing",
            "users missing from logs",
            "no username in logs",
            "ip showing instead of user",
            "ip instead of username",
            "only ip in logs",
            "traffic log no user",
            "log shows ip not user",
            # IP-to-user mapping
            "ip-user mapping",
            "ip user mapping",
            "ip to user mapping",
            "user mapping",
            "show user ip-user-mapping",
            "user mapping missing",
            "user mapping empty",
            "user mapping table",
            "mapping does not exist",
            "no mapping",
            "stale mapping",
            "wrong user mapped",
            "user-id mapping",
            "userid mapping",
            "mapping cache",
            "clear user-cache",
            "user cache",
            # Domain controller / agent
            "user-id agent",
            "userid agent",
            "windows user-id agent",
            "user id agent",
            "integrated user-id agent",
            "show user user-id-agent",
            "user-id agent disconnected",
            "user-id agent down",
            "uia",
            "domain controller user-id",
            "dc user-id",
            "server monitor user-id",
            "show user server-monitor",
            "server monitor state",
            "user-id agent state",
            # WMI / WinRM
            "wmi user-id",
            "winrm user-id",
            "wmi permissions",
            "winrm permissions",
            "wmi broken",
            "wmi user id",
            "winrm user id",
            "dcom user-id",
            "cimv2 user-id",
            "remote launch dcom",
            "event log reader",
            "event log readers",
            "distributed com users",
            "wmi agentless",
            "agentless user-id",
            # Windows event IDs
            "event id 4624",
            "event 4624",
            "4624",
            "event id 4768",
            "event 4768",
            "4768",
            "event id 4769",
            "event 4769",
            "4769",
            "event id 4770",
            "event 4770",
            "kerberos event user-id",
            "audit policy user-id",
            "security log user-id",
            "windows security events user-id",
            "auditpol user-id",
            # GlobalProtect User-ID
            "globalprotect user-id",
            "gp user-id",
            "gp userid",
            "globalprotect mapping",
            "gp mapping",
            "vpn user mapping",
            "vpn user-id",
            "remote user not mapped",
            "remote user no user-id",
            "globalprotect users not showing",
            "gp users not in logs",
            # LDAP / group mapping
            "group mapping user-id",
            "ldap group mapping",
            "group mapping",
            "user group mapping",
            "show user group-mapping",
            "group include list",
            "ldap base dn",
            "base dn user-id",
            "base dn group mapping",
            "group policy user-id",
            "user in logs but group policy fails",
            "group based policy not matching",
            "group policy not matching",
            "nested groups user-id",
            "multi-domain user-id",
            "global catalog user-id",
            # Include / exclude networks
            "include exclude networks",
            "user-id include networks",
            "user-id exclude networks",
            "user-id subnet scope",
            "vpn pool user-id",
            "show user include-exclude",
            # Redistribution
            "user-id redistribution",
            "userid redistribution",
            "user id redistribution",
            "redistribute user-id",
            "hub spoke user-id",
            "panorama user-id redistribution",
            # Captive portal / auth portal
            "captive portal user-id",
            "authentication portal",
            "auth portal user-id",
            "captive portal mapping",
            # Terminal server / VDI / RDS
            "terminal server user-id",
            "terminal server agent",
            "rds user-id",
            "vdi user-id",
            "citrix user-id",
            "shared endpoint user-id",
            # Debug / log commands
            "useridd.log",
            "useridd log",
            "debug user-id",
            "debug userid",
            "show log userid",
            "user-id log",
            "userid log",
            "subtype eq userid",
            "show user user-ids",
            "debug user-id log-ip-user-mapping",
            "debug user-id refresh-group-mapping",
            # DHCP / timeout
            "user-id timeout",
            "user-id cache expiry",
            "mapping timeout",
            "dhcp user-id",
            "ip reuse user-id",
            # Direct KB ID references
            "kb-sec-uid",
            "kb-sec-uid-001",
        ],
    },
    "pan_ipsec_vpn_troubleshooting.md": {
        "kb_id": "KB-PAN-VPN-001",
        "title": "IPsec Site-to-Site VPN — Tunnel Up, Traffic Does Not Pass",
        "triggers": [
            # Core VPN symptoms
            "tunnel up no traffic",
            "vpn tunnel up no traffic",
            "ipsec tunnel up no traffic",
            "tunnel green no traffic",
            "vpn not passing traffic",
            "vpn traffic not passing",
            "site-to-site vpn not working",
            "site to site vpn not working",
            "s2s vpn not working",
            "ipsec not working",
            "ipsec tunnel not working",
            "vpn broken",
            "vpn issue",
            "vpn problem",
            "tunnel broken",
            "ipsec broken",
            # Proxy-ID / traffic selector
            "proxy-id",
            "proxy id",
            "proxyid",
            "proxy id mismatch",
            "proxy-id mismatch",
            "traffic selector",
            "traffic selector mismatch",
            "crypto acl",
            "interesting traffic",
            "encryption domain",
            "selector mismatch",
            "ipsec selector",
            "phase 2 selector",
            "proxy id 0.0.0.0",
            "0.0.0.0 proxy",
            # IKE general
            "ike",
            "ikev1",
            "ikev2",
            "ike phase 1",
            "ike phase 2",
            "ike sa",
            "ipsec sa",
            "phase 1",
            "phase 2",
            "ike negotiation",
            "ike mismatch",
            "ike version mismatch",
            "ikev1 vs ikev2",
            "ike gateway",
            "show vpn ike-sa",
            "show vpn ipsec-sa",
            "ikemgr.log",
            "ikemgr log",
            # PSK
            "psk",
            "pre-shared key",
            "pre shared key",
            "preshared key",
            "psk mismatch",
            "psk rotation",
            "psk change",
            "psk update",
            "authentication failure vpn",
            "vpn auth failure",
            "ike auth failure",
            # PFS
            "pfs",
            "perfect forward secrecy",
            "pfs mismatch",
            "pfs group",
            "pfs group mismatch",
            "dh group mismatch",
            "dh group vpn",
            "phase 2 rekey",
            "sa rekey",
            "ipsec rekey",
            # MTU / MSS / DF-bit
            "vpn mtu",
            "ipsec mtu",
            "tunnel mtu",
            "mtu vpn",
            "mss vpn",
            "mss clamping",
            "df-bit",
            "df bit",
            "dont fragment",
            "pmtud vpn",
            "pmtu vpn",
            "fragmentation vpn",
            "ipsec overhead",
            "vpn large packets",
            "large packets vpn",
            "small packets work large fail",
            "ping works but transfer fails",
            "smb vpn stall",
            "gre ipsec mtu",
            "gre over ipsec",
            "gre ipsec",
            "gre mtu",
            "ipsec esp overhead",
            # NAT + VPN
            "nat exemption",
            "vpn nat exemption",
            "no-nat vpn",
            "no nat vpn",
            "nat over vpn",
            "nat vpn exemption",
            "vpn nat issue",
            "nat breaks vpn",
            "masquerade vpn",
            "nat exemption rule",
            # Routing + VPN
            "vpn routing",
            "route vpn",
            "tunnel interface route",
            "vpn route",
            "route based vpn",
            "route-based vpn",
            "policy based vpn",
            "policy-based vpn",
            "encaps decaps",
            "encapsulation counter",
            "decapsulation counter",
            "encaps increasing",
            "decaps not increasing",
            "show vpn flow",
            # Security policy + VPN
            "vpn security policy",
            "vpn policy block",
            "tunnel zone",
            "vpn zone",
            "trust to vpn",
            "vpn to trust",
            # Inter-vendor VPN
            "palo cisco vpn",
            "pan to cisco vpn",
            "asa vpn palo",
            "cisco asa vpn",
            "pan asa",
            "fortinet vpn palo",
            "fortigate vpn palo",
            "pan fortigate",
            "azure vpn palo",
            "pan azure vpn",
            "azure vpn gateway",
            "azure s2s vpn",
            "azure site to site",
            # VPN tunnel flapping
            "vpn flapping",
            "tunnel flapping",
            "ipsec flapping",
            "tunnel drops",
            "vpn drops",
            "vpn reconnect",
            "sa expires",
            "ipsec sa expires",
            "vpn lifetime",
            "phase 2 lifetime",
            # Commands
            "show vpn",
            "test vpn ike-sa",
            "test vpn ipsec-sa",
            "show running tunnel",
            "debug dataplane packet-diag",
            # Direct KB ID references
            "kb-pan-vpn",
            "kb-pan-vpn-001",
        ],
    },
    "pan_panorama_troubleshooting.md": {
        "kb_id": "KB-PAN-MGMT-001",
        "title": "Panorama — Commit, Push & Management Plane Design",
        "triggers": [
            # Core Panorama terms
            "panorama",
            "panorama commit",
            "panorama push",
            "panorama commit fail",
            "panorama push fail",
            "commit to panorama",
            "commit failed panorama",
            "push failed panorama",
            "push to devices",
            "commit and push",
            "panorama commit error",
            "panorama push error",
            "panorama commit stuck",
            "panorama push stuck",
            "panorama commit pending",
            "panorama push pending",
            "panorama commit blocked",
            "panorama push blocked",
            "panorama out of sync",
            "device out of sync",
            "out of sync panorama",
            "panorama sync",
            "panorama in sync",
            "panorama not syncing",
            # Two-stage commit model
            "two stage commit",
            "two-stage commit",
            "commit push",
            "commit then push",
            "panorama push vs commit",
            "panorama commit vs push",
            "candidate config panorama",
            "running config panorama",
            "panorama config",
            # Template stack
            "template stack",
            "template stacks",
            "template stack precedence",
            "panorama template",
            "panorama templates",
            "template variable",
            "template variables",
            "template override",
            "device-specific variable",
            "device specific variable",
            "variable panorama",
            "stack variable",
            "template inheritance",
            "template hierarchy",
            "base template",
            "child template",
            "template push",
            "template commit",
            "network template",
            # Device group
            "device group",
            "device groups",
            "device group hierarchy",
            "shared device group",
            "device group precedence",
            "panorama device group",
            "device group commit",
            "device group push",
            "device group policy",
            "device group object",
            "device group rule",
            "pre-rule",
            "post-rule",
            "pre rule panorama",
            "post rule panorama",
            "local rule panorama",
            # Shared objects / collision
            "shared object",
            "shared objects",
            "object collision",
            "duplicate object panorama",
            "panorama object conflict",
            "object override",
            "shared address object",
            "shared security profile",
            "shared panorama",
            # Offline / air-gapped upgrades
            "offline upgrade panorama",
            "offline panorama upgrade",
            "air-gapped panorama",
            "air gapped panorama",
            "panorama offline",
            "panorama offline upgrade",
            "panorama upgrade offline",
            "panorama no internet",
            "panorama upgrade without internet",
            "panorama content update offline",
            "panorama software update offline",
            "panorama scp upgrade",
            "panorama tftp upgrade",
            "panorama image upload",
            # SAML / admin authentication
            "saml panorama",
            "panorama saml",
            "saml admin role panorama",
            "panorama saml admin",
            "panorama 11.1 saml",
            "panorama saml 11.1",
            "saml attribute mapping panorama",
            "panorama saml attribute",
            "saml role attribute panorama",
            "panorama azure saml",
            "panorama entra id",
            "panorama azure ad",
            "panorama okta",
            "panorama idp",
            "panorama sso",
            "panorama admin authentication",
            "panorama admin login",
            "panorama saml auth",
            "panorama authentication profile",
            "panorama admin role",
            "panorama role assignment",
            "panorama superuser",
            "panorama admin access",
            # Log Collector
            "log collector",
            "log collectors",
            "dedicated log collector",
            "mixed mode panorama",
            "panorama mixed mode",
            "panorama log collector",
            "log collector group",
            "collector group",
            "collector groups",
            "log collector sizing",
            "panorama log storage",
            "panorama log capacity",
            "log forwarding panorama",
            "panorama logging",
            "panorama log",
            "panorama logs",
            "m-100",
            "m-200",
            "m-500",
            "m-600",
            "m-series panorama",
            "panorama m-series",
            "panorama appliance",
            "panorama hardware",
            "panorama vm",
            "panorama virtual",
            "panorama ova",
            # Commit locks
            "commit lock",
            "commit locks",
            "configuration lock",
            "config lock",
            "panorama lock",
            "panorama commit lock",
            "locked commit",
            "panorama locked",
            "who has commit lock",
            "release commit lock",
            "clear commit lock",
            # Management plane / connectivity
            "panorama connectivity",
            "device not connected panorama",
            "firewall not connected panorama",
            "panorama device down",
            "panorama device disconnected",
            "panorama show devices",
            "panorama not reachable",
            "panorama connection",
            "panorama tcp port",
            "panorama port 3978",
            "panorama 3978",
            "panorama ssl 28443",
            "panorama port 28443",
            "panorama 28443",
            "panorama licensing",
            "panorama license",
            "panorama connected",
            # CLI / show commands
            "show jobs all",
            "show panorama-status",
            "panorama-status",
            "show panorama status",
            "request commit",
            "request push",
            "show commit-locks",
            "debug panorama",
            "tail mp-log panorama",
            "mp-log panorama",
            "panorama cli",
            # High availability Panorama
            "panorama ha",
            "panorama high availability",
            "panorama primary",
            "panorama secondary",
            "panorama active passive",
            "panorama failover",
            "panorama peer",
            # General management
            "panorama manage",
            "panorama management",
            "panorama design",
            "panorama architecture",
            "panorama deployment",
            "panorama best practice",
            "panorama sizing",
            "panorama scale",
            "panorama capacity",
            "manage panorama",
            "panorama overview",
            "panorama guide",
            "panorama setup",
            # Direct KB ID references
            "kb-pan-mgmt",
            "kb-pan-mgmt-001",
        ],
    },
    "cortex_xdr_xsiam_troubleshooting.md": {
        "kb_id": "KB-CORTEX-XDR-001",
        "title": "Cortex XDR / XSIAM — Alert Grouping, Network Location, Broker VM & Cloud Identity Engine",
        "triggers": [
            # Core product terms
            "cortex xdr",
            "cortex xsiam",
            "xdr",
            "xsiam",
            "cortex xdr xsiam",
            "xdr xsiam",
            "cortex platform",
            # Alert grouping / incident noise
            "alert grouping",
            "alert grouping xdr",
            "alert grouping xsiam",
            "incident grouping",
            "incident noise",
            "alerts grouped",
            "alerts merged",
            "unrelated alerts grouped",
            "false grouping",
            "over grouping",
            "over-grouping",
            "xdr over grouping",
            "xsiam over grouping",
            "incident merging",
            "alert stitching",
            "grouping rule",
            "grouping rules",
            "xdr grouping rule",
            "incident management xdr",
            "alert grouping rule",
            "xdr incident",
            "xsiam incident",
            "xdr incident noise",
            "xsiam incident noise",
            "grouping magnet",
            "similarity threshold",
            "grouping threshold",
            "alert correlation xdr",
            "xdr correlation",
            "xsiam correlation",
            "causality analysis",
            "causality chain",
            "process lineage xdr",
            # NAT / shared IP grouping
            "nat grouping",
            "nat ip grouping",
            "shared egress ip",
            "shared nat ip",
            "nat egress xdr",
            "proxy ip grouping",
            "vpn ip grouping",
            "shared proxy xdr",
            "shared nat xdr",
            "nat alert grouping",
            "nat incident xdr",
            "nat incident xsiam",
            "shared ip xdr",
            "shared ip xsiam",
            "network exclusions xdr",
            "network exclusions xsiam",
            "add nat to exclusions",
            "exclude nat xdr",
            "grouping exclusion",
            "network exclusion list",
            # Network Location
            "network location",
            "network location xdr",
            "network location xsiam",
            "network location detection",
            "host firewall profile",
            "firewall profile xdr",
            "wrong firewall profile",
            "wrong profile xdr",
            "internal profile xdr",
            "external profile xdr",
            "network location config",
            "network location misconfiguration",
            "endpoint profile",
            "endpoint policy xdr",
            "endpoint location",
            "internal external classification",
            "ldap connectivity test",
            "dns resolution test",
            "ldap test xdr",
            "dns test xdr",
            "domain controller test xdr",
            "dc reachability xdr",
            "ldap port 389",
            "ldap port 636",
            # GP split-tunnel + network location
            "split tunnel xdr",
            "globalprotect split tunnel xdr",
            "gp split tunnel network location",
            "split tunnel profile",
            "split tunnel firewall profile",
            "gp tunnel network location",
            "gp internal external",
            "globalprotect internal external",
            "remote endpoint internal profile",
            "off premise internal profile",
            "vpn internal profile",
            "cytool",
            "cytool runtime policy",
            "cytool policy show",
            "cyvera logs",
            # Broker VM
            "broker vm",
            "broker vm syslog",
            "broker vm ingestion",
            "broker vm xdr",
            "broker vm xsiam",
            "syslog broker vm",
            "syslog ingestion xdr",
            "syslog ingestion xsiam",
            "syslog collector xdr",
            "syslog collector xsiam",
            "cortex syslog",
            "xdr syslog",
            "xsiam syslog",
            "broker vm health",
            "broker status",
            "broker syslog status",
            "syslog not normalized",
            "syslog raw dataset",
            "xdr raw syslog",
            "xdr_raw_syslog",
            "syslog parser",
            "xdr parser",
            "xsiam parser",
            "syslog parser xdr",
            "parser test xdr",
            "parser mismatch xdr",
            "broker vm tls",
            "syslog tls",
            "syslog tcp xdr",
            "syslog udp xdr",
            "broker vm native",
            "native integration xdr",
            "native integration xsiam",
            "native vs syslog xdr",
            "broker vm vs native",
            # Dataset / XQL
            "xql",
            "xql query",
            "xdr dataset",
            "xsiam dataset",
            "xdr_alerts",
            "xdr_data",
            "palo_alto_cortex_xdr",
            "palo_alto_ngfw_traffic",
            "palo_alto_ngfw_threat",
            "panw_ngfw_raw",
            "dataset schema xdr",
            "dataset schema xsiam",
            "xdm field",
            "xdm mapping",
            "xdm field mapping",
            "xql field",
            "xql dataset",
            "xql join",
            "cross dataset join",
            "xdr field name",
            "xsiam field name",
            "event_timestamp xdr",
            "ingestion time xdr",
            "_time xdr",
            "actor_process_image_name",
            "action_remote_ip",
            "src_ip xdr",
            "dataset naming",
            "dataset name xdr",
            "wrong dataset name",
            "xdr dataset discovery",
            "xql autocomplete",
            # Cloud Identity Engine
            "cloud identity engine",
            "cie",
            "cie activation",
            "cloud identity engine activation",
            "cie activate",
            "cie xdr",
            "cie xsiam",
            "cie fail",
            "cie activation fail",
            "cie activation error",
            "cie permissions",
            "cie role",
            "hub superuser",
            "hub.paloaltonetworks.com",
            "pan hub",
            "paloaltonetworks hub",
            "cortex hub",
            "hub role",
            "hub admin",
            "hub superuser role",
            "cortex admin role",
            "xdr instance admin",
            "xsiam admin",
            "cie app role",
            "common services identity",
            "csp account",
            "cortex gateway role",
            "activation console",
            "cie onboarding",
            "cie directory sync",
            "cloud identity agent",
            "cie active directory",
            "cie azure ad",
            "cie okta",
            "cie user group sync",
            "cie identity provider",
            "cie tenant",
            "cie region",
            # SOC / analyst workflows
            "xdr soc runbook",
            "xsiam soc runbook",
            "xdr analyst",
            "xsiam analyst",
            "incident annotation xdr",
            "split incident xdr",
            "merge incident xdr",
            "xdr playbook",
            "xsiam playbook",
            "nat lookup xdr",
            "shared infrastructure lookup",
            # Detection engineering / XQL correlation
            "xql correlation rule",
            "correlation rule xdr",
            "correlation rule xsiam",
            "yaml correlation",
            "xsiam yaml rule",
            "custom detection xdr",
            "detection engineering xdr",
            # Direct KB ID references
            "kb-cortex-xdr",
            "kb-cortex-xdr-001",
            "kb-cortex-xdr-xsiam",
            "kb-cortex-xdr-xsiam-combined",
            "kb-cortex-xdr-xsiam-combined-001",
        ],
    },
    "prisma_access_routing_troubleshooting.md": {
        "kb_id": "KB-PA-ROUTING-001",
        "title": "Prisma Access — Routing, Service Connections, Remote Networks, BGP & Advanced Troubleshooting",
        "triggers": [
            # Core product terms
            "prisma access",
            "prisma access routing",
            "prisma access troubleshoot",
            "prisma access network",
            "prisma access private access",
            "prisma access connectivity",
            "prisma access traffic",
            "prisma access forwarding",
            "prisma access bgp",
            "prisma access vpn",
            "prisma access ipsec",
            # Mobile users / private apps
            "prisma access mobile user",
            "mobile user private app",
            "mobile user cannot reach",
            "prisma access cannot reach",
            "prisma access private app",
            "private application access",
            "private app unreachable",
            "prisma access app access",
            "globalprotect private app",
            "gp private app",
            "mobile user app",
            "globalprotect cannot reach app",
            "gp cannot reach private",
            "prisma access user cannot connect",
            "authenticated but cannot reach",
            "connected but cannot access",
            "prisma access no route",
            "prisma access missing route",
            # Service connections
            "service connection",
            "service connections",
            "sc prisma access",
            "prisma service connection",
            "service connection down",
            "service connection up",
            "service connection tunnel",
            "service connection bgp",
            "service connection failover",
            "service connection ha",
            "service connection routing",
            "service connection route",
            "service connection no traffic",
            "service connection broken",
            "service connection troubleshoot",
            "primary service connection",
            "secondary service connection",
            "corporate access node",
            "can prisma access",
            # Remote networks
            "remote network",
            "remote networks",
            "remote network routing",
            "remote network tunnel",
            "remote network bgp",
            "remote network routes missing",
            "remote network no route",
            "remote network unreachable",
            "remote network troubleshoot",
            "remote network site",
            "branch prisma access",
            "branch site prisma access",
            "prisma access branch",
            "prisma access site",
            "remote site prisma",
            "remote site routing",
            "tunnel up routes missing",
            "tunnel up no routes",
            "tunnel up missing routes",
            "ipsec up no routes",
            "vpn up no routes",
            "vpn tunnel up routes missing",
            # BGP Prisma Access
            "bgp prisma access",
            "prisma bgp",
            "prisma access bgp session",
            "prisma access bgp not established",
            "prisma access bgp down",
            "prisma access bgp routes",
            "prisma access bgp peer",
            "prisma access bgp as",
            "prisma access bgp as 65000",
            "bgp route advertisement prisma",
            "bgp prefix prisma access",
            "bgp filter prisma access",
            "bgp route map prisma",
            "bgp prefix list prisma",
            "bgp established no traffic",
            "bgp route too broad",
            "bgp default route advertised",
            "bgp 0.0.0.0/0 prisma",
            "bgp default route prisma access",
            "bgp route too narrow",
            "bgp 32 host routes",
            "bgp host routes only",
            "bgp advertisement prisma",
            "bgp rib prisma",
            "bgp loc-rib prisma",
            "bgp rib-out prisma",
            "bgp rib-in prisma",
            "as path loop prisma",
            "as loop prisma",
            "as 65000 prisma",
            "bgp as number prisma",
            "bgp peer as prisma",
            "bgp hold timer prisma",
            "bgp keepalive prisma",
            "bgp flapping prisma",
            "bgp tcp 179",
            "bgp soft-reconfiguration prisma",
            # Mobile user IP pool / return route
            "mobile user pool",
            "mobile user ip pool",
            "mobile user subnet",
            "mobile user /24",
            "prisma mobile user pool",
            "mobile user return route",
            "return route mobile user",
            "hq return route prisma",
            "data center return route prisma",
            "mobile user not routable",
            "mobile user unreachable from hq",
            "mobile user pool route",
            "advertise mobile user pool",
            "mobile user pool bgp",
            "summarize mobile user routes",
            # Static route vs BGP
            "static route prisma access",
            "static route override bgp prisma",
            "static bgp conflict prisma",
            "static overrides bgp",
            "stale static route prisma",
            "prisma access static route",
            "route precedence prisma",
            "static route wins bgp prisma",
            # NAT and identity
            "source nat prisma access",
            "snat prisma access",
            "nat prisma access",
            "no-nat prisma access",
            "no nat service connection",
            "nat breaks user-id prisma",
            "nat user-id prisma access",
            "user-id lost prisma access",
            "device-id lost prisma access",
            "identity lost prisma",
            "snat breaks user-id",
            "nat identity prisma",
            "user-id prisma access",
            "device-id prisma access",
            "no nat rule prisma",
            "nat exemption prisma",
            # Hairpinning
            "hairpin prisma access",
            "hairpinning prisma access",
            "traffic hairpin prisma",
            "prisma access hairpin",
            "unexpected hairpin prisma",
            "routing loop prisma",
            "branch to branch prisma",
            "branch to branch routing",
            "do not export routes",
            "re-advertisement prisma",
            # Route propagation
            "route propagation prisma",
            "prisma access route propagation",
            "route distribution prisma",
            "prisma access route table",
            "show routing route prisma",
            "show routing protocol bgp",
            "routing table prisma access",
            "prefix propagation prisma",
            "route leak prisma",
            "route leakage prisma",
            # Infrastructure gateway
            "infrastructure gw",
            "infrastructure gateway prisma",
            "prisma gw",
            "infra gw",
            # Tunnel monitoring / failover
            "tunnel monitoring prisma",
            "dpd prisma access",
            "bfd prisma access",
            "dead peer detection prisma",
            "prisma access failover",
            "service connection failover slow",
            "sc failover",
            "primary preferred prisma",
            "prisma access preemption",
            "asymmetric routing prisma",
            # Traffic flow
            "traffic flow prisma access",
            "prisma access traffic flow",
            "split tunnel prisma access",
            "full tunnel prisma access",
            "prisma access internet",
            "prisma access egress",
            # Strata Cloud Manager / Panorama
            "strata cloud manager routing",
            "cloud manager prisma access",
            "panorama prisma access",
            "panorama managed prisma",
            "cloud managed prisma",
            # CPE commands
            "show ip bgp summary prisma",
            "show ip bgp neighbors advertised",
            "clear ip bgp soft",
            "soft-reconfiguration inbound",
            "route-map branch out",
            "ip prefix-list prisma",
            # Diagnostic commands
            "show routing route",
            "show vpn tunnel prisma",
            "show vpn ike-sa prisma",
            "show vpn ipsec-sa prisma",
            "show user ip-user-mapping",
            "debug dataplane packet-diag prisma",
            # Direct KB ID references
            "kb-pa-routing",
            "kb-pa-routing-001",
        ],
    },
    "scm_aiops_troubleshooting.md": {
        "kb_id": "KB-SCM-AIOPS-0001",
        "title": "AIOps & Strata Cloud Manager — Onboarding Telemetry, Configuration, Validation & Troubleshooting",
        "triggers": [
            # Core product terms
            "aiops",
            "aiops ngfw",
            "aiops for ngfw",
            "aiops premium",
            "aiops free",
            "strata cloud manager",
            "scm",
            "scm aiops",
            "scm telemetry",
            "scm onboarding",
            "scm troubleshoot",
            "strata cloud manager troubleshoot",
            "strata cloud manager onboarding",
            "strata cloud manager setup",
            "strata cloud manager no data",
            "strata cloud manager not working",
            "strata cloud manager device",
            "stratacloudmanager",
            # Telemetry
            "device telemetry",
            "pan telemetry",
            "panos telemetry",
            "telemetry not working",
            "telemetry not uploading",
            "telemetry upload fail",
            "telemetry failed",
            "telemetry disabled",
            "telemetry enable",
            "enable telemetry",
            "telemetry region",
            "telemetry region mismatch",
            "telemetry not sending",
            "telemetry not received",
            "telemetry configuration",
            "configure telemetry",
            "telemetry collect",
            "request device-telemetry collect-now",
            "show device-telemetry",
            "device-telemetry",
            "telemetry auto-enabled",
            "telemetry auto enabled",
            "telemetry health",
            "telemetry stats",
            "telemetry status",
            "telemetry troubleshoot",
            "device telemetry troubleshoot",
            "device telemetry upload",
            "device telemetry region",
            "device telemetry log",
            "device_telemetry.log",
            "device_telemetry_curl.log",
            # Cortex Data Lake
            "cortex data lake",
            "cdl",
            "cdl telemetry",
            "cdl connectivity",
            "cdl not connected",
            "cdl upload fail",
            "cdl ingestion",
            "cdl region",
            "cdl link",
            "link panorama cdl",
            "link to cdl",
            "cdl logging",
            "cdl logging endpoint",
            "cdl fqdn",
            "logging.prod.datapath",
            "api.prod.datapath",
            "cortex data lake region",
            "cortex data lake activation",
            "activate cortex data lake",
            "cdl activation",
            "cdl tenant",
            "cdl tenant id",
            # Strata Logging Service
            "strata logging service",
            "sls",
            "sls region",
            "sls telemetry",
            "logging service",
            "logging service connectivity",
            "logging service status",
            # Device health / BPA
            "device health score",
            "health score",
            "aiops health score",
            "scm health score",
            "best practice assessment",
            "bpa",
            "bpa scm",
            "bpa aiops",
            "bpa stale",
            "bpa not loading",
            "bpa awaiting data",
            "awaiting data scm",
            "bpa no data",
            "best practice check",
            "scm bpa",
            "aiops bpa",
            "configuration snapshot",
            "config snapshot scm",
            "snapshot not updating",
            # Software Upgrade Advisor
            "software upgrade advisor",
            "upgrade advisor",
            "aiops upgrade advisor",
            "scm upgrade advisor",
            "upgrade risk score",
            # Predictive failure
            "predictive failure",
            "predictive analytics aiops",
            "aiops predictive",
            "predictive failure detection",
            # Connectivity / network requirements
            "telemetry fqdn",
            "telemetry port",
            "telemetry tcp 443",
            "telemetry tcp 444",
            "telemetry tcp 3978",
            "port 3978 telemetry",
            "port 444 telemetry",
            "paloaltonetworks cloud connectivity",
            "scm fqdn",
            "aiops fqdn",
            "telemetry blocked",
            "telemetry firewall block",
            "telemetry proxy",
            "proxy telemetry",
            "proxy blocking telemetry",
            "proxy block scm",
            "ssl inspection telemetry",
            "ssl inspect scm",
            "ssl inspection blocking telemetry",
            "decryption telemetry",
            "certificate pinning telemetry",
            "telemetry ssl",
            "google-base app-id",
            "paloalto-device-telemetry",
            "app-id telemetry",
            # Service routes
            "service route telemetry",
            "telemetry service route",
            "service route scm",
            "management interface telemetry",
            "mgt interface telemetry",
            "telemetry management interface",
            "telemetry source interface",
            # Device certificate
            "device certificate",
            "device certificate status",
            "show device-certificate status",
            "device certificate expired",
            "device certificate invalid",
            "device certificate missing",
            "device cert",
            "device cert expired",
            "device cert scm",
            "certificate telemetry",
            # DNS / NTP
            "dns telemetry",
            "ntp telemetry",
            "clock skew telemetry",
            "clock skew cdl",
            "ntp scm",
            "dns scm",
            "time sync telemetry",
            "jwt authentication fail",
            "jwt token fail",
            "300 seconds clock skew",
            # CSP / tenant / licensing
            "csp account",
            "csp tenant",
            "tenant association",
            "device association scm",
            "wrong tenant scm",
            "device not in scm",
            "device missing scm",
            "serial number scm",
            "scm license",
            "aiops license",
            "sls license",
            "aiops entitlement",
            "scm entitlement",
            "request license info",
            # Panorama CloudConnector
            "cloudconnector",
            "cloud connector plugin",
            "cloudconnector plugin",
            "panorama cloudconnector",
            "cloudconnector panorama",
            "aiops plugin panorama",
            "panorama aiops plugin",
            "old aiops plugin",
            "aiops plugin conflict",
            "install cloudconnector",
            "enable cloudconnector",
            "request plugins cloudconnector",
            "show plugins installed",
            "panorama plugin scm",
            "cloudconnector enable",
            # Cloud management
            "cloud management status",
            "show cloud-management-status",
            "scm managed firewall",
            "cloud managed firewall",
            "scm onboard firewall",
            "cloud managed device",
            "scm device management",
            "advanced routing engine scm",
            # M-700 specific
            "m-700 telemetry",
            "m700 telemetry",
            "m-700 cdl",
            "m700 cdl",
            "m-700 log collector telemetry",
            "panorama m-700 scm",
            "collector group cdl",
            "log collector cdl",
            # Activity insights / dashboards
            "activity insights",
            "activity insights scm",
            "scm dashboard",
            "scm dashboard no data",
            "scm no data",
            "scm stale data",
            "scm command center",
            "command center scm",
            "insights scm",
            "device health scm",
            # Auto-enabled gotcha
            "telemetry auto enabled not uploading",
            "auto enabled telemetry fail",
            # Direct KB ID references
            "kb-scm-aiops",
            "kb-scm-aiops-0001",
        ],
    },
}


# Common English words that carry no topical signal — excluded from scoring.
# Deliberately small: PAN-specific short tokens (ssl, tls, vpn, gre, nat, ca)
# must NOT be in this list even though they're short.
_STOPWORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "must", "shall", "can",
    "i", "you", "he", "she", "it", "we", "they", "them", "their",
    "his", "her", "its", "our", "my", "your",
    "this", "that", "these", "those",
    "what", "which", "who", "when", "where", "why", "how",
    "and", "or", "but", "if", "then", "than", "so", "yet", "nor",
    "in", "on", "at", "by", "for", "with", "about", "into", "through",
    "to", "from", "up", "of", "out", "not", "no",
    "very", "just", "also", "all", "any", "each", "every",
    "more", "most", "other", "some", "such", "only", "own", "same",
    "get", "use", "make", "see", "set", "used", "using", "made",
    "one", "two", "new", "old", "good", "bad", "true", "false",
})


def _parse_kb_sections(content: str) -> list:
    """
    Split a markdown document into sections at the ## and ### header levels.
    Each entry: {"heading": str, "level": int, "body": str}
    where body is the raw markdown for that section (heading line included).
    The document preamble (before the first ## header) is kept separately
    with heading "__preamble__" and level 0.
    """
    lines = content.split("\n")
    sections = []
    current = {"heading": "__preamble__", "level": 0, "lines": []}

    for line in lines:
        m = re.match(r"^(#{2,3})\s+(.+)", line)
        if m:
            body = "\n".join(current["lines"]).strip()
            if body:
                sections.append({
                    "heading": current["heading"],
                    "level":   current["level"],
                    "body":    body,
                })
            current = {
                "heading": m.group(2).strip(),
                "level":   len(m.group(1)),
                "lines":   [line],
            }
        else:
            current["lines"].append(line)

    body = "\n".join(current["lines"]).strip()
    if body:
        sections.append({
            "heading": current["heading"],
            "level":   current["level"],
            "body":    body,
        })

    return sections


def _kb_relevant_sections(kb_entry: dict, message: str) -> str:
    """
    Return only the sections of a KB article that are relevant to the question.

    Algorithm:
      1. Tokenise the question into meaningful 3-char+ words (minus stopwords).
      2. Score each ## / ### section by counting how many question words appear
         in it (case-insensitive substring match — so "cert" matches "certificate").
      3. Threshold = max(2, 30% of the top section's score).
      4. Return all sections at or above the threshold.
      5. Fall back to the full article when:
         - No sections are parsed (shouldn't happen with current KB files)
         - No question words could be extracted (very short / single-word query)
         - max_score ≤ 1 (single keyword hit — not enough signal to filter)
         - No sections score above the threshold (no signal → return all)
         - ≥ 70% of sections qualify (question is broad → return all)
    """
    # Exclude preamble entries from scoring; keep only ## / ### content sections
    sections = [s for s in kb_entry.get("sections", []) if s["heading"] != "__preamble__"]
    if not sections:
        return kb_entry["content"]

    # Tokenise: lowercase alpha-numeric words ≥ 3 chars, not in stopwords
    raw_words = re.findall(r"[a-z][a-z0-9/.-]{2,}", message.lower())
    question_words = frozenset(w for w in raw_words if w not in _STOPWORDS)
    if not question_words:
        return kb_entry["content"]

    # Score: count unique question words found anywhere in the section text
    def _score(sec: dict) -> int:
        text = (sec["heading"] + " " + sec["body"]).lower()
        return sum(1 for w in question_words if w in text)

    scored = [(sec, _score(sec)) for sec in sections]
    max_score = max(s for _, s in scored)

    if max_score == 0:
        return kb_entry["content"]

    # A max score of 1 means only one keyword appeared once across all sections —
    # not enough signal to meaningfully filter. Return the full article.
    if max_score <= 1:
        return kb_entry["content"]

    threshold = max(2, int(max_score * 0.30))
    relevant = [sec for sec, s in scored if s >= threshold]

    # Broad question → return the full article
    if len(relevant) >= len(sections) * 0.70:
        return kb_entry["content"]

    if not relevant:
        # No sections cleared the threshold — not enough signal to pick sections.
        # Return the full article rather than an arbitrary single section.
        return kb_entry["content"]

    return "\n\n---\n\n".join(sec["body"] for sec in relevant)


def _build_kb_index() -> list:
    """
    Load KB .md files from KB_DIR, pairing each with its trigger phrases and
    parsed sections. Only files listed in _KB_TRIGGER_MAP are loaded.
    Returns list of dicts: {kb_id, title, content, sections, triggers}.
    """
    if not KB_DIR.exists():
        return []
    entries = []
    for kb_file in sorted(KB_DIR.glob("*.md")):
        meta = _KB_TRIGGER_MAP.get(kb_file.name)
        if not meta:
            continue
        try:
            content = kb_file.read_text(encoding="utf-8").strip()
            if not content:
                continue
            entries.append({
                "kb_id":    meta["kb_id"],
                "title":    meta["title"],
                "content":  content,
                "sections": _parse_kb_sections(content),
                "triggers": frozenset(t.lower() for t in meta["triggers"]),
            })
        except Exception as exc:
            logger.warning("KB load failed for %s: %s", kb_file.name, exc)
    return entries


_KB_INDEX: list = _build_kb_index()


def _kb_match(message: str) -> Optional[dict]:
    """
    Return the first KB entry whose trigger phrases appear in the user's message,
    or None if no article matches. Case-insensitive substring search.
    """
    msg_lower = message.lower()
    for entry in _KB_INDEX:
        for phrase in entry["triggers"]:
            if phrase in msg_lower:
                return entry
    return None

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AuthRequest(BaseModel):
    email: str
    password: str

_ALLOWED_MODELS = {
    "auto",
    "claude-opus-4-7",
    "claude-sonnet-4-6",
    "claude-haiku-4-5-20251001",
}
_MAX_TOKENS_CAP      = 4096
MAX_QUERY_WEIGHT     = 3      # max cost multiplier for a single query
MAX_CONFIG_LEN_FREE  = 8_000  # chars above which free-tier config counts as MAX_QUERY_WEIGHT queries

# Pasted-image limits (per chat turn). Anthropic vision models accept PNG, JPEG,
# GIF, and WEBP. Cap count + per-image size to keep latency and token cost sane.
MAX_IMAGES_PER_MSG = 4
MAX_IMAGE_BYTES    = 5 * 1024 * 1024  # 5 MB decoded
_ALLOWED_IMAGE_MEDIA_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}

# ---------------------------------------------------------------------------
# Model routing — picks the best model based on question complexity
# ---------------------------------------------------------------------------

_COMPLEX_KEYWORDS = {
    "audit", "analyze", "analyse", "review", "migrate", "migration",
    "shadow", "rulebase", "rule base", "security posture", "convert",
    "compliance", "assessment", "inventory", "all rules", "all policies",
    "best practices", "troubleshoot", "diagnose", "forensic",
}

def _select_model(message: str, config_text: Optional[str], tier: str = "pro") -> str:
    """Route to the right model based on message and config complexity.

    Free tier is always Haiku — fast, cost-controlled, and appropriate for
    the 10-query/week limit. Paid tiers get full auto-routing.
    """
    # Free tier locked to Haiku regardless of message or config size
    if tier == "free":
        return "claude-haiku-4-5-20251001"

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


class ChatImage(BaseModel):
    """A pasted screenshot or uploaded image, base64-encoded."""
    media_type: str
    data: str  # base64-encoded image bytes

    @field_validator("media_type", mode="before")
    @classmethod
    def validate_media_type(cls, v):
        v = (v or "").lower().strip()
        if v not in _ALLOWED_IMAGE_MEDIA_TYPES:
            raise ValueError(
                f"Unsupported image type {v!r}. "
                f"Allowed: {sorted(_ALLOWED_IMAGE_MEDIA_TYPES)}"
            )
        return v

    @field_validator("data", mode="before")
    @classmethod
    def validate_data(cls, v):
        if not isinstance(v, str) or not v:
            raise ValueError("Image data must be a non-empty base64 string.")
        # Decoded-size guard: base64 grows bytes by ~4/3, so cap raw length too.
        if len(v) > MAX_IMAGE_BYTES * 4 // 3 + 16:
            raise ValueError(
                f"Image too large (max {MAX_IMAGE_BYTES // (1024*1024)} MB)."
            )
        try:
            decoded_len = len(base64.b64decode(v, validate=True))
        except Exception:
            raise ValueError("Image data is not valid base64.")
        if decoded_len > MAX_IMAGE_BYTES:
            raise ValueError(
                f"Image too large ({decoded_len:,} bytes, "
                f"max {MAX_IMAGE_BYTES:,})."
            )
        return v


class ChatRequest(BaseModel):
    message: str
    config_text: Optional[str] = None
    model: Optional[str] = "auto"
    max_tokens: Optional[int] = 2048
    conversation_id: Optional[str] = None
    product_id: Optional[str] = None  # informational only; not used server-side
    images: Optional[List[ChatImage]] = None

    @field_validator("model", mode="before")
    @classmethod
    def validate_model(cls, v):
        if v not in _ALLOWED_MODELS:
            return "auto"
        return v

    @field_validator("max_tokens", mode="before")
    @classmethod
    def cap_tokens(cls, v):
        return min(int(v or 2048), _MAX_TOKENS_CAP)

    @field_validator("images", mode="before")
    @classmethod
    def cap_images(cls, v):
        if v is None:
            return None
        if not isinstance(v, list):
            raise ValueError("images must be a list.")
        if len(v) > MAX_IMAGES_PER_MSG:
            raise ValueError(
                f"Too many images (max {MAX_IMAGES_PER_MSG} per message)."
            )
        return v

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

_MAX_HISTORY_TURNS = 40  # cap at 20 user/assistant pairs to stay well within context limits

def load_conversation_history(conversation_id: str, limit: int = _MAX_HISTORY_TURNS) -> list:
    """
    Load recent messages for a conversation from SQLite.
    Returns a list of {"role": ..., "content": ...} dicts in chronological order.
    The frontend always sends history=[] as a placeholder; the DB is the source of truth.
    `limit` caps how many recent messages are returned (local mode makes this
    user-configurable; cloud uses the default).
    """
    with get_db() as db:
        # rowid is SQLite's monotonically-increasing implicit primary key — used
        # as a tiebreaker because save_messages writes the user and assistant
        # rows of a single turn with the same created_at, and without a stable
        # secondary sort the pair can flip on load. A flipped pair sends
        # [assistant, user] back to the model, which some chat templates
        # reject with "No user query found in messages."
        rows = db.execute(
            "SELECT role, content FROM messages "
            "WHERE conversation_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
            (conversation_id, limit),
        ).fetchall()
    # fetchall is newest-first (DESC); reverse for chronological order
    return [{"role": r["role"], "content": r["content"]} for r in reversed(rows)]

def build_messages(req: ChatRequest, db_history: list = None) -> list:
    """
    Build the messages list for the Anthropic API call.
    db_history (from SQLite) is preferred over req.history (from client).

    When images are attached, the final user turn becomes a list of content
    blocks (image blocks first, then a single text block) so the Anthropic
    vision API can read the screenshots alongside the question.
    """
    messages = []
    history_source = db_history if db_history is not None else []
    for turn in history_source:
        role    = turn.get("role")    if isinstance(turn, dict) else turn.role
        content = turn.get("content") if isinstance(turn, dict) else turn.content
        if role in ("user", "assistant"):
            messages.append({"role": role, "content": content})
    user_text = req.message
    if req.config_text and req.config_text.strip():
        user_text = (
            "I am pasting the following PAN-OS configuration or CLI output for you to analyze:\n\n"
            f"```\n{req.config_text.strip()}\n```\n\n"
            f"{req.message}"
        )
    if req.images:
        # Anthropic vision content blocks. Placing images first matches the
        # documented pattern and helps the model anchor its answer to them.
        blocks = [
            {
                "type": "image",
                "source": {
                    "type":       "base64",
                    "media_type": img.media_type,
                    "data":       img.data,
                },
            }
            for img in req.images
        ]
        blocks.append({"type": "text", "text": user_text})
        messages.append({"role": "user", "content": blocks})
    else:
        messages.append({"role": "user", "content": user_text})
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


# ---------------------------------------------------------------------------
# Settings endpoints — chat provider preferences
# ---------------------------------------------------------------------------

def _effective_provider(settings: dict, tier: Optional[str]) -> str:
    """Return the provider we'll actually use, applying tier-based hard-lock.

    The 'local' tier is sold as a stay-on-your-machine plan, so the cloud
    provider is unavailable. Other tiers can choose either.
    """
    pref = settings.get("chat_provider", "cloud")
    if tier == "local":
        return "local"
    return "cloud" if pref not in _VALID_PROVIDERS else pref


@app.get("/api/settings")
def get_settings():
    settings = load_settings()
    tier = _session_cache.get("tier")
    return {
        "settings": settings,
        "tier": tier,
        "effective_provider": _effective_provider(settings, tier),
        # Tier-aware availability so the UI can grey out the cloud option for
        # local-tier users (and the local option for free-tier users until
        # they upgrade — Phase 3 will toggle this).
        "providers_available": {
            "cloud": tier != "local",
            "local": tier in (None, "local", "pro", "max", "owner"),
        },
    }


@app.post("/api/settings")
def update_settings(req: SettingsPayload):
    current = load_settings()
    tier    = _session_cache.get("tier")

    new_provider = req.chat_provider if req.chat_provider is not None else current["chat_provider"]
    if new_provider not in _VALID_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Invalid chat_provider {new_provider!r}.")

    # Hard-lock: Local-tier accounts cannot enable cloud mode. They must
    # upgrade their subscription to unlock the Anthropic-backed experience.
    if tier == "local" and new_provider == "cloud":
        raise HTTPException(
            status_code=403,
            detail=(
                "Your account is on the Local tier — cloud chat is not included. "
                "Upgrade to Pro at adkcyber.com/pan-copilot.html to enable cloud mode."
            ),
        )

    updated = dict(current)
    updated["chat_provider"] = new_provider
    if req.local_base_url is not None:
        updated["local_base_url"] = req.local_base_url.strip()
    if req.local_model is not None:
        updated["local_model"] = req.local_model.strip()
    if req.local_api_key is not None:
        updated["local_api_key"] = req.local_api_key.strip()
    if req.local_history_turns is not None:
        updated["local_history_turns"] = req.local_history_turns
    if req.local_context_tokens is not None:
        updated["local_context_tokens"] = req.local_context_tokens
    if req.local_truncate_config is not None:
        updated["local_truncate_config"] = req.local_truncate_config
    if req.local_max_tokens is not None:
        updated["local_max_tokens"] = req.local_max_tokens
    if req.local_temperature is not None:
        updated["local_temperature"] = req.local_temperature
    if req.local_supports_vision is not None:
        updated["local_supports_vision"] = req.local_supports_vision
    updated = _normalize_settings(updated)
    save_settings(updated)
    return {
        "ok": True,
        "settings": updated,
        "effective_provider": _effective_provider(updated, tier),
    }


@app.post("/api/local_llm/test")
def test_local_llm(req: LocalLLMTestRequest):
    """Fire a single 1-token completion to verify the local LLM is reachable.

    Returns latency in ms on success, or a friendly error on failure. Used by
    the "Test connection" button in the settings panel.
    """
    base = (req.base_url or "").rstrip("/")
    if not base:
        raise HTTPException(status_code=400, detail="Base URL is required.")
    url = f"{base}/chat/completions"
    body = {
        "model": req.model or "qwen2.5:14b",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,
        "stream": False,
    }
    headers = {"Content-Type": "application/json"}
    if req.api_key:
        headers["Authorization"] = f"Bearer {req.api_key}"
    started = time.time()
    try:
        r = httpx.post(url, json=body, headers=headers, timeout=15.0)
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Cannot reach {url}. Is your local LLM server running? "
                "Try 'ollama serve' or enable the server toggle in LM Studio."
            ),
        )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Connection timed out after 15s.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Connection failed: {e}")
    latency_ms = int((time.time() - started) * 1000)
    if r.status_code >= 400:
        raise HTTPException(
            status_code=r.status_code,
            detail=f"Server returned HTTP {r.status_code}: {r.text[:300]}",
        )
    return {"ok": True, "latency_ms": latency_ms, "model": req.model}


@app.get("/api/local_llm/models")
def list_local_llm_models(
    base_url: str,
    api_key: Optional[str] = None,
):
    """Proxy OpenAI GET /v1/models for the settings model picker."""
    base = (base_url or "").rstrip("/")
    if not base:
        raise HTTPException(status_code=400, detail="base_url is required.")
    url = f"{base}/models"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        r = httpx.get(url, headers=headers, timeout=15.0)
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail=f"Cannot reach {url}. Is your local LLM server running?",
        )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Listing models timed out after 15s.")
    if r.status_code >= 400:
        raise HTTPException(
            status_code=r.status_code,
            detail=f"Server returned HTTP {r.status_code}: {r.text[:300]}",
        )
    try:
        payload = r.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="Model list response was not valid JSON.")
    models: list[str] = []
    for item in payload.get("data") or []:
        if isinstance(item, dict):
            mid = item.get("id") or item.get("name")
            if mid:
                models.append(str(mid))
        elif isinstance(item, str):
            models.append(item)
    models = sorted(set(models))
    return {"models": models, "count": len(models)}


@app.post("/api/local_llm/context_estimate")
def local_context_estimate(req: LocalContextEstimateRequest):
    """Estimate local context usage for UI warnings (no LLM call)."""
    settings = load_settings()
    tier = _session_cache.get("tier")
    provider = _effective_provider(settings, tier)
    est = estimate_local_context_usage(
        config_text=req.config_text or "",
        message=req.message or "",
        conversation_id=req.conversation_id,
        settings=settings,
    )
    est["effective_provider"] = provider
    est["truncate_config_enabled"] = bool(settings.get("local_truncate_config", True))
    return est


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
# Cisco → PAN-OS migration (local only — no cloud API)
# ---------------------------------------------------------------------------

MIGRATE_MAX_BYTES = 5_000_000


@app.get("/api/migrate/coverage")
async def api_migrate_coverage():
    """Feature coverage matrix for multi-vendor Config Migration."""
    from migration.coverage import coverage_snapshot

    return coverage_snapshot()


@app.post("/api/migrate")
async def api_migrate(
    cisco_config: UploadFile = File(...),
    base_xml: UploadFile | None = File(None),
    vsys: str = Form("vsys1"),
    mode: str = Form("firewall"),
    device_group: str = Form(""),
    source_vendor: str = Form("auto"),
):
    """Convert third-party or Palo config to PAN-OS SET + merged XML. Runs locally."""
    from migration.pipeline import MigrationOptions, build_zip_bundle, run_migration

    allowed = {".txt", ".xml", ".log", ".cfg", ".conf", ".json"}
    ext = Path(cisco_config.filename or "").suffix.lower()
    if ext not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported config type '{ext}'. Allowed: {', '.join(sorted(allowed))}",
        )

    raw = await cisco_config.read(MIGRATE_MAX_BYTES + 1)
    if len(raw) > MIGRATE_MAX_BYTES:
        raise HTTPException(status_code=413, detail="Source config too large. Max 5 MB.")

    try:
        cisco_text = raw.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode source config as UTF-8 text.")

    base_text: str | None = None
    if base_xml and base_xml.filename:
        bx = await base_xml.read(MIGRATE_MAX_BYTES + 1)
        if len(bx) > MIGRATE_MAX_BYTES:
            raise HTTPException(status_code=413, detail="Base XML too large. Max 5 MB.")
        try:
            base_text = bx.decode("utf-8", errors="replace")
        except Exception:
            raise HTTPException(status_code=400, detail="Could not decode base XML.")

    opts = MigrationOptions(
        vsys=vsys or "vsys1",
        mode=mode if mode in ("firewall", "panorama") else "firewall",
        device_group=device_group or None,
        source_vendor=(source_vendor or "auto").lower(),
    )
    result = run_migration(cisco_text, base_text, options=opts)
    bundle = build_zip_bundle(result)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in bundle.items():
            zf.writestr(name, content)
    buf.seek(0)

    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="pan_migration_bundle.zip"'},
    )


@app.post("/api/migrate/preview")
async def api_migrate_preview(
    cisco_config: UploadFile = File(...),
    base_xml: UploadFile | None = File(None),
    vsys: str = Form("vsys1"),
    mode: str = Form("firewall"),
    device_group: str = Form(""),
    source_vendor: str = Form("auto"),
):
    """JSON preview of migration stats and report (no ZIP). Local only."""
    from migration.pipeline import MigrationOptions, run_migration

    raw = await cisco_config.read(MIGRATE_MAX_BYTES + 1)
    if len(raw) > MIGRATE_MAX_BYTES:
        raise HTTPException(status_code=413, detail="Source config too large. Max 5 MB.")
    cisco_text = raw.decode("utf-8", errors="replace")
    base_text = None
    if base_xml and base_xml.filename:
        base_text = (await base_xml.read(MIGRATE_MAX_BYTES + 1)).decode("utf-8", errors="replace")

    opts = MigrationOptions(
        vsys=vsys or "vsys1",
        mode=mode if mode in ("firewall", "panorama") else "firewall",
        device_group=device_group or None,
        source_vendor=(source_vendor or "auto").lower(),
    )
    result = run_migration(cisco_text, base_text, options=opts)
    return {
        "source_format": result.report.source_format,
        "source_vendor": result.ir.source_vendor,
        "summary": result.report.summary(),
        "report": result.report.to_dict(),
        "counts": {
            "set_commands": len(result.set_commands),
            "addresses": len(result.ir.addresses),
            "security_rules": len(result.ir.security_rules),
            "nat_rules": len(result.ir.nat_rules),
            "vpn_tunnels": len(result.ir.vpn_tunnels),
        },
    }

# ---------------------------------------------------------------------------
# Chat — streaming
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Chat providers — cloud (Anthropic) and local (OpenAI-compatible)
# ---------------------------------------------------------------------------
# Both providers expose the same generator contract:
#   yields one of:
#     ("token", str)           — a text chunk to stream to the client
#     ("done",  dict)          — final usage dict { input_tokens, output_tokens }
#     ("error", str)           — terminal error message
# /chat/stream below picks one based on settings.chat_provider and translates
# the events into our existing SSE wire format. The frontend doesn't change.

def _to_openai_messages(messages: list) -> list:
    """Convert our Anthropic-shape messages to OpenAI chat-completions shape.

    The main difference is image blocks:
      Anthropic: {"type":"image", "source":{"type":"base64","media_type":...,"data":...}}
      OpenAI:    {"type":"image_url", "image_url":{"url":"data:<mime>;base64,<b64>"}}
    """
    out = []
    for m in messages:
        content = m.get("content")
        if isinstance(content, list):
            new_blocks = []
            for block in content:
                btype = block.get("type")
                if btype == "image":
                    src = block.get("source", {}) or {}
                    mime = src.get("media_type", "image/png")
                    data = src.get("data", "")
                    new_blocks.append({
                        "type": "image_url",
                        "image_url": {"url": f"data:{mime};base64,{data}"},
                    })
                else:
                    new_blocks.append(block)
            out.append({"role": m["role"], "content": new_blocks})
        else:
            out.append({"role": m["role"], "content": content})
    return out


def _stream_anthropic(api_key: str, model: str, system: str, messages: list, max_tokens: int):
    """Sync generator: yields (kind, payload) tuples sourced from Anthropic's SDK."""
    try:
        client = anthropic.Anthropic(api_key=api_key)
        with client.messages.stream(
            model=model, max_tokens=max_tokens, system=system, messages=messages,
        ) as stream:
            for text in stream.text_stream:
                yield ("token", text)
            final = stream.get_final_message()
            yield ("done", {
                "input_tokens":  final.usage.input_tokens,
                "output_tokens": final.usage.output_tokens,
            })
    except anthropic.AuthenticationError:
        yield ("error", "API key error. Please contact support@adkcyber.com.")
    except anthropic.RateLimitError:
        yield ("error", "Rate limit reached. Try again in a moment.")
    except anthropic.APIError as e:
        yield ("error", str(e))


def _stream_openai_compat(
    base_url: str,
    model:    str,
    system:   str,
    messages: list,
    api_key:  Optional[str],
    max_tokens: int,
    temperature: Optional[float] = None,
):
    """Sync generator: yields (kind, payload) for an OpenAI-compatible server.

    Works with Ollama (/v1/chat/completions), LM Studio, llama.cpp-server, vLLM.
    Translates image content blocks to image_url shape before sending.
    """
    base = (base_url or "").rstrip("/")
    if not base:
        yield ("error", "Local LLM base URL is not set. Open Settings and enter one (default Ollama: http://localhost:11434/v1).")
        return
    url = f"{base}/chat/completions"
    body = {
        "model": model or "qwen2.5:14b",
        "messages": [{"role": "system", "content": system}] + _to_openai_messages(messages),
        "max_tokens": max_tokens,
        "stream": True,
    }
    if temperature is not None:
        body["temperature"] = temperature
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    input_tokens = 0
    output_tokens = 0
    output_text_chars = 0
    saw_reasoning = False
    reasoning_closed = False
    try:
        with httpx.Client(timeout=httpx.Timeout(connect=10.0, read=None, write=30.0, pool=10.0)) as client:
            with client.stream("POST", url, json=body, headers=headers) as resp:
                if resp.status_code >= 400:
                    try:
                        detail = resp.read().decode("utf-8", errors="replace")
                    except Exception:
                        detail = ""
                    yield ("error", f"Local LLM returned HTTP {resp.status_code}: {detail[:300]}")
                    return
                for raw_line in resp.iter_lines():
                    line = raw_line.strip() if isinstance(raw_line, str) else raw_line.decode("utf-8", errors="replace").strip()
                    if not line or not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if payload == "[DONE]":
                        break
                    try:
                        evt = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    choices = evt.get("choices") or []
                    if choices:
                        delta = (choices[0] or {}).get("delta") or {}
                        # Reasoning models (Qwen3, DeepSeek-R1, etc.) stream
                        # their chain-of-thought in a separate `reasoning_content`
                        # field. We don't surface the reasoning text in the chat
                        # — only the final answer — so the chat stays compact.
                        # Instead we emit thinking_start / thinking_end events so
                        # the frontend can show a "researching the answer…"
                        # indicator while reasoning is in progress.
                        reasoning = delta.get("reasoning_content")
                        if reasoning and not saw_reasoning:
                            yield ("thinking_start", None)
                            saw_reasoning = True
                        chunk = delta.get("content")
                        if chunk:
                            if saw_reasoning and not reasoning_closed:
                                yield ("thinking_end", None)
                                reasoning_closed = True
                            # Some models inline reasoning as <think>…</think> in
                            # content; drop the literal tags so they don't render.
                            chunk = chunk.replace("<think>", "").replace("</think>", "")
                            output_text_chars += len(chunk)
                            yield ("token", chunk)
                    usage = evt.get("usage") or {}
                    if usage:
                        input_tokens  = int(usage.get("prompt_tokens")     or usage.get("input_tokens")  or 0)
                        output_tokens = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
        # If the stream closed cleanly but produced no content at all, the
        # server didn't time out from our side — it returned an empty reply.
        # Surface a real error instead of fabricating a "1 out" success, which
        # masks model-name mismatches, thinking models that exhaust max_tokens
        # inside <think>, and chat-template bugs in the local server.
        if output_text_chars == 0 and not saw_reasoning:
            yield ("error",
                f"Local LLM returned an empty response (model: {model!r}). "
                "Common causes: (1) the model name doesn't match what your local "
                "server has loaded; (2) it's a reasoning model whose entire "
                "max_tokens budget was spent inside <think> with no answer "
                "emitted — raise max_tokens or disable thinking mode; "
                "(3) the loaded chat template is producing empty output. "
                "Check your local server's log for details.")
            return
        # Many local servers omit a token-count usage block. Fall back to a
        # crude char-based estimate so the UI's "N out" counter isn't always 0.
        if not output_tokens:
            output_tokens = max(1, output_text_chars // 4)
        yield ("done", {"input_tokens": input_tokens, "output_tokens": output_tokens})
    except httpx.ConnectError:
        yield ("error", f"Cannot reach local LLM at {url}. Is your server running? (Ollama: 'ollama serve'; LM Studio: enable the server toggle.)")
    except httpx.ReadTimeout:
        yield ("error", "Local LLM timed out while reading the response. Try a smaller model or increase your server's timeout.")
    except Exception as e:
        yield ("error", f"Local LLM request failed: {e}")


@app.post("/chat/stream")
def chat_stream(req: ChatRequest):
    if not _session_cache.get("token"):
        raise HTTPException(
            status_code=401,
            detail="Not logged in. Please sign in to use ADK Cyber AI."
        )

    # ── KB short-circuit ────────────────────────────────────────────────────
    # If the user's question matches a local KB article, serve it directly.
    # No Anthropic API call, no quota consumed, no latency. Skip when the user
    # pasted screenshots — the question can't be answered from a text KB alone.
    kb_entry = None if req.images else _kb_match(req.message)
    if kb_entry:
        conv_id = get_or_create_conversation(req.conversation_id)

        # Extract only the sections relevant to this specific question
        relevant_content = _kb_relevant_sections(kb_entry, req.message)
        kb_response = (
            f"📚 *{kb_entry['kb_id']} · Local knowledge base · 0 tokens used*\n\n"
            "---\n\n"
            + relevant_content
        )

        def kb_event_generator():
            # Send the full KB response as one token so the markdown renderer
            # always receives complete tables and code blocks — never a mid-row slice.
            yield f"data: {json.dumps({'type': 'token', 'text': kb_response})}\n\n"
            save_messages(conv_id, req.message, kb_response)
            auto_title(conv_id, req.message)
            yield (
                "data: " + json.dumps({
                    "type":               "done",
                    "model":              "local-kb",
                    "input_tokens":       0,
                    "output_tokens":      0,
                    "conversation_id":    conv_id,
                    "queries_used":       _session_cache.get("queries_used"),
                    "queries_limit":      _session_cache.get("queries_limit"),
                    "queries_remaining":  _session_cache.get("queries_remaining"),
                    "period":             _session_cache.get("period", "weekly"),
                    "tier":               _session_cache.get("tier"),
                    "redactions":         0,
                }) + "\n\n"
            )

        return StreamingResponse(
            kb_event_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
    # ── End KB short-circuit ────────────────────────────────────────────────

    token      = _session_cache.get("token")
    tier       = _session_cache.get("tier", "free")
    settings   = load_settings()
    provider   = _effective_provider(settings, tier)
    config_len = len(req.config_text or "")

    # ── Cloud-only preflight: quota + API key checks ────────────────────────
    # In local mode the user is running the LLM on their own hardware, so we
    # skip the license-server quota check entirely (no per-query cost).
    if provider == "cloud":
        api_key = _session_cache.get("anthropic_key")
        if not api_key:
            raise HTTPException(
                status_code=401,
                detail="Session key missing. Please log out and log back in."
            )

        # Free tier: large config pastes count as MAX_QUERY_WEIGHT queries to
        # reflect the higher token cost. The user is warned in the UI first.
        query_weight = MAX_QUERY_WEIGHT if (tier == "free" and config_len > MAX_CONFIG_LEN_FREE) else 1
        check = _license_post("/query/check", {"token": token, "weight": query_weight})

        if not check.get("allowed", False):
            base_detail = check.get("detail", "Query limit reached.")
            if query_weight == MAX_QUERY_WEIGHT:
                detail = (
                    f"{base_detail} "
                    f"This config paste ({config_len:,} chars) counted as {MAX_QUERY_WEIGHT} queries — "
                    f"free tier charges {MAX_QUERY_WEIGHT} queries for configs over {MAX_CONFIG_LEN_FREE:,} characters. "
                    f"Upgrade to Pro for full config analysis with advanced models: "
                    f"adkcyber.com/pan-copilot.html"
                )
            else:
                detail = base_detail
            raise HTTPException(status_code=429, detail=detail)

        # Sync usage into session cache
        for key in ("queries_used", "queries_limit", "queries_remaining", "period"):
            if check.get(key) is not None:
                _session_cache[key] = check[key]
        if check.get("weekly_used") is not None:
            _session_cache["weekly_used"] = check["weekly_used"]
    else:
        api_key = None  # not used in local mode

    if provider == "local" and req.images and not settings.get("local_supports_vision"):
        raise HTTPException(
            status_code=400,
            detail=(
                "Screenshot upload is disabled for local LLM mode. Enable "
                "'Model supports vision' in Settings → My local LLM, or switch to Cloud."
            ),
        )

    # Strip credential values from config + message before transmitting (applies
    # to both providers — even your own local LLM shouldn't see PAN admin
    # passwords or pre-shared keys in plaintext if redaction is in flight).
    cfg_sanitized, cfg_redactions = (
        sanitize_config_text(req.config_text)
        if req.config_text and req.config_text.strip()
        else (req.config_text or "", 0)
    )
    msg_sanitized, msg_redactions = sanitize_config_text(req.message)
    total_redactions = cfg_redactions + msg_redactions

    config_truncated = False
    if provider == "local" and cfg_sanitized and cfg_sanitized.strip():
        cfg_sanitized, config_truncated = _truncate_config_for_local(
            cfg_sanitized,
            settings=settings,
            message=msg_sanitized,
            conversation_id=req.conversation_id,
        )

    sanitized_req = req.copy(update={
        "config_text": cfg_sanitized,
        "message":     msg_sanitized,
    })

    conv_id    = get_or_create_conversation(req.conversation_id)
    if provider == "local":
        hist_limit = int(settings.get("local_history_turns") or _MAX_HISTORY_TURNS)
        db_history = load_conversation_history(conv_id, limit=hist_limit)
    else:
        db_history = load_conversation_history(conv_id)
    messages   = build_messages(sanitized_req, db_history=db_history)

    # ── Resolve model + system prompt + provider stream ─────────────────────
    if provider == "local":
        resolved_model = (settings.get("local_model") or "qwen2.5:14b").strip()
        system_prompt  = SYSTEM_PROMPT_LOCAL
        local_max = int(settings.get("local_max_tokens") or 8192)
        local_temp = float(settings.get("local_temperature") if settings.get("local_temperature") is not None else 0.2)
        provider_iter  = _stream_openai_compat(
            base_url   = settings.get("local_base_url") or "",
            model      = resolved_model,
            system     = system_prompt,
            messages   = messages,
            api_key    = (settings.get("local_api_key") or None),
            max_tokens = local_max,
            temperature = local_temp,
        )
    else:
        # Cloud: free tier locked to Haiku; auto routes by complexity; vision
        # gets a Sonnet floor.
        if tier == "free":
            resolved_model = "claude-haiku-4-5-20251001"
        elif req.model == "auto":
            resolved_model = _select_model(req.message, req.config_text, tier=tier)
            if req.images and resolved_model == "claude-haiku-4-5-20251001":
                resolved_model = "claude-sonnet-4-6"
        else:
            resolved_model = req.model
        system_prompt = SYSTEM_PROMPT
        provider_iter = _stream_anthropic(
            api_key    = api_key,
            model      = resolved_model,
            system     = system_prompt,
            messages   = messages,
            max_tokens = req.max_tokens,
        )

    def event_generator():
        full_reply = []
        usage = {"input_tokens": 0, "output_tokens": 0}
        terminal_error = None
        for kind, payload in provider_iter:
            if kind == "token":
                full_reply.append(payload)
                yield f"data: {json.dumps({'type': 'token', 'text': payload})}\n\n"
            elif kind == "thinking_start":
                yield f"data: {json.dumps({'type': 'thinking_start'})}\n\n"
            elif kind == "thinking_end":
                yield f"data: {json.dumps({'type': 'thinking_end'})}\n\n"
            elif kind == "done":
                usage = payload
            elif kind == "error":
                terminal_error = payload

        if terminal_error:
            yield f"data: {json.dumps({'type': 'error', 'detail': terminal_error})}\n\n"
            return

        reply_text = "".join(full_reply)
        # Persist a text-only summary so DB history stays text-only. The marker
        # tells future turns (and the user reviewing history) that images were
        # part of the original turn even though the bytes aren't replayed.
        n_imgs = len(req.images) if req.images else 0
        persisted_msg = req.message
        if n_imgs:
            suffix = f"\n\n[{n_imgs} image{'s' if n_imgs != 1 else ''} attached]"
            persisted_msg = (persisted_msg or "").rstrip() + suffix
        save_messages(conv_id, persisted_msg, reply_text)
        auto_title(conv_id, persisted_msg)

        yield "data: " + json.dumps({
            "type":              "done",
            "model":             resolved_model,
            "provider":          provider,
            "input_tokens":      usage.get("input_tokens", 0),
            "output_tokens":     usage.get("output_tokens", 0),
            "conversation_id":   conv_id,
            "queries_used":      _session_cache.get("queries_used") if provider == "cloud" else None,
            "queries_limit":     _session_cache.get("queries_limit") if provider == "cloud" else None,
            "queries_remaining": _session_cache.get("queries_remaining") if provider == "cloud" else None,
            "period":            _session_cache.get("period", "weekly") if provider == "cloud" else None,
            "tier":              _session_cache.get("tier"),
            "redactions":        total_redactions,
            "config_truncated":  config_truncated if provider == "local" else False,
        }) + "\n\n"

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


def _fetch_update_info(force: bool = False) -> dict:
    global _update_cache, _update_cache_ts
    now = time.time()
    if not force and _update_cache and now - _update_cache_ts < _UPDATE_CACHE_TTL:
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
def get_version(force: int = 0):
    return _fetch_update_info(force=bool(force))


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
            # Silent install relaunches PAN Copilot.exe in installer.iss CurStepChanged
            # (skipifsilent blocks [Run]; /RESTARTAPPLICATIONS is unreliable after taskkill).
            subprocess.Popen([str(tmp), "/SILENT", "/FORCECLOSEAPPLICATIONS"])

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

        except Exception as exc:
            logger.error("Auto-update download/install failed: %s", exc)

    threading.Thread(target=_download_and_run, daemon=True).start()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Palo Alto Networks Security Advisories
# ---------------------------------------------------------------------------
# Background task polls https://security.paloaltonetworks.com/rss.xml hourly
# and stores HIGH/CRITICAL advisories in the local SQLite cache. The frontend
# pulls active (non-dismissed) advisories via /api/advisories and renders a
# banner so users can't miss a real-world threat affecting their PAN gear.

_ADVISORY_RSS_URL        = "https://security.paloaltonetworks.com/rss.xml"
_ADVISORY_POLL_INTERVAL  = 3600.0  # seconds — Palo Alto publishes infrequently
_ADVISORY_INITIAL_DELAY  = 10.0    # let uvicorn finish booting before first fetch
_ADVISORY_DISPLAY_LIMIT  = 25      # cap banner list — shouldn't ever realistically fire

_SEVERITY_RE = re.compile(
    r"\(Severity:\s*(CRITICAL|HIGH|MEDIUM|LOW|NONE)\)", re.IGNORECASE
)
_CVE_RE = re.compile(r"(CVE-\d{4}-\d+)")


def _parse_advisories_xml(xml_bytes: bytes) -> list:
    """Parse Palo Alto's RSS feed → list of advisory dicts.

    Severity is encoded *only* in the <title>, e.g.
      "CVE-2026-0264 PAN-OS: Heap-Based Buffer Overflow ... (Severity: HIGH)"
    so we extract it via regex. Items lacking a recognisable severity tag or
    CVE id are skipped silently.
    """
    items = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        logger.info("Advisory feed XML parse error: %s", e)
        return items
    for item in root.findall(".//item"):
        title_el = item.find("title")
        link_el  = item.find("link")
        date_el  = item.find("pubDate")
        if title_el is None or link_el is None:
            continue
        title = (title_el.text or "").strip()
        link  = (link_el.text or "").strip()
        pub   = (date_el.text or "").strip() if date_el is not None else ""
        m_sev = _SEVERITY_RE.search(title)
        m_cve = _CVE_RE.search(title) or (_CVE_RE.search(link) if link else None)
        if not m_sev or not m_cve:
            continue
        items.append({
            "cve_id":   m_cve.group(1),
            "title":    title,
            "link":     link,
            "severity": m_sev.group(1).upper(),
            "pub_date": pub,
        })
    return items


def _persist_advisories(items: list, bootstrap: bool) -> int:
    """Insert new HIGH/CRITICAL advisories. Returns count inserted.

    bootstrap=True means the local advisories table is empty (fresh install or
    first run after upgrade). In that case we auto-dismiss every advisory we
    see so the user only ever gets alerted about advisories published AFTER
    they installed PAN Copilot — they don't want a wall of 200 historical
    CVEs the first time they open the app.
    """
    now = now_iso()
    inserted = 0
    with get_db() as db:
        for it in items:
            if it["severity"] not in ("CRITICAL", "HIGH"):
                continue
            cur = db.execute(
                "INSERT OR IGNORE INTO advisories "
                "(cve_id, title, link, severity, pub_date, seen_at, dismissed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    it["cve_id"], it["title"], it["link"], it["severity"],
                    it["pub_date"], now,
                    now if bootstrap else None,
                ),
            )
            if cur.rowcount:
                inserted += 1
        db.commit()
    return inserted


async def _fetch_palo_advisories_once() -> int:
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            r = await client.get(_ADVISORY_RSS_URL)
            r.raise_for_status()
            items = _parse_advisories_xml(r.content)
    except Exception as e:
        logger.info("Advisory feed fetch failed: %s", e)
        return 0
    with get_db() as db:
        existing = db.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
    bootstrap = (existing == 0)
    inserted = _persist_advisories(items, bootstrap=bootstrap)
    if inserted and not bootstrap:
        logger.info("Advisory feed: %d new HIGH/CRITICAL advisor%s inserted",
                    inserted, "y" if inserted == 1 else "ies")
    return inserted


_advisory_task: Optional[asyncio.Task] = None


async def _advisory_poll_loop():
    try:
        await asyncio.sleep(_ADVISORY_INITIAL_DELAY)
        while True:
            await _fetch_palo_advisories_once()
            await asyncio.sleep(_ADVISORY_POLL_INTERVAL)
    except asyncio.CancelledError:
        pass


@app.on_event("startup")
async def _start_advisory_poller():
    global _advisory_task
    _advisory_task = asyncio.create_task(_advisory_poll_loop())


@app.on_event("shutdown")
async def _stop_advisory_poller():
    if _advisory_task and not _advisory_task.done():
        _advisory_task.cancel()


class AdvisoryDismiss(BaseModel):
    cve_id: str


@app.get("/api/advisories")
async def get_advisories(force: int = 0):
    """Return active (non-dismissed) HIGH/CRITICAL advisories.

    Pass ?force=1 to trigger a fresh RSS fetch before answering — useful for
    the manual recheck button in the UI.
    """
    if force:
        await _fetch_palo_advisories_once()
    with get_db() as db:
        rows = db.execute(
            "SELECT cve_id, title, link, severity, pub_date, seen_at "
            "FROM advisories WHERE dismissed_at IS NULL "
            "ORDER BY pub_date DESC, seen_at DESC LIMIT ?",
            (_ADVISORY_DISPLAY_LIMIT,),
        ).fetchall()
    return {"advisories": [dict(r) for r in rows]}


@app.post("/api/advisories/dismiss")
def dismiss_advisory(req: AdvisoryDismiss):
    cve = req.cve_id.strip()
    if not _CVE_RE.fullmatch(cve):
        raise HTTPException(status_code=400, detail="Invalid CVE id.")
    with get_db() as db:
        db.execute(
            "UPDATE advisories SET dismissed_at = ? "
            "WHERE cve_id = ? AND dismissed_at IS NULL",
            (now_iso(), cve),
        )
        db.commit()
    return {"ok": True}


@app.post("/api/advisories/dismiss_all")
def dismiss_all_advisories():
    """Mark every currently-active advisory as dismissed.

    Used by the banner's top-level close button. After this, the banner stays
    hidden until the next hourly poll inserts a brand-new HIGH/CRITICAL row
    (INSERT OR IGNORE means we won't resurface anything we've already seen).
    """
    with get_db() as db:
        cur = db.execute(
            "UPDATE advisories SET dismissed_at = ? WHERE dismissed_at IS NULL",
            (now_iso(),),
        )
        db.commit()
    return {"ok": True, "dismissed": cur.rowcount}


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
    if not hmac.compare_digest(req.shutdown_token, SHUTDOWN_TOKEN):
        raise HTTPException(status_code=403, detail="Forbidden.")
    def _do_exit():
        time.sleep(0.4)
        if _uvicorn_server is not None:
            _uvicorn_server.should_exit = True
    threading.Thread(target=_do_exit, daemon=True).start()
    return {"ok": True}
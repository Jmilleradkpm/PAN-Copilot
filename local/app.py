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


SYSTEM_PROMPT = load_system_prompt() + _RESPONSE_STYLE_ADDENDUM

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
        except Exception:
            pass
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

_MAX_HISTORY_TURNS = 40  # cap at 20 user/assistant pairs to stay well within context limits

def load_conversation_history(conversation_id: str) -> list:
    """
    Load recent messages for a conversation from SQLite.
    Returns a list of {"role": ..., "content": ...} dicts in chronological order.
    The frontend always sends history=[] as a placeholder; the DB is the source of truth.
    """
    with get_db() as db:
        rows = db.execute(
            "SELECT role, content FROM messages "
            "WHERE conversation_id = ? ORDER BY created_at DESC LIMIT ?",
            (conversation_id, _MAX_HISTORY_TURNS),
        ).fetchall()
    # fetchall is newest-first (DESC); reverse for chronological order
    return [{"role": r["role"], "content": r["content"]} for r in reversed(rows)]

def build_messages(req: ChatRequest, db_history: list = None) -> list:
    """
    Build the messages list for the Anthropic API call.
    db_history (from SQLite) is preferred over req.history (from client).
    """
    messages = []
    history_source = db_history if db_history is not None else []
    for turn in history_source:
        role    = turn.get("role")    if isinstance(turn, dict) else turn.role
        content = turn.get("content") if isinstance(turn, dict) else turn.content
        if role in ("user", "assistant"):
            messages.append({"role": role, "content": content})
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

    # ── KB short-circuit ────────────────────────────────────────────────────
    # If the user's question matches a local KB article, serve it directly.
    # No Anthropic API call, no quota consumed, no latency.
    kb_entry = _kb_match(req.message)
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

    api_key = _session_cache.get("anthropic_key")
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Session key missing. Please log out and log back in."
        )

    token      = _session_cache["token"]
    tier       = _session_cache.get("tier", "free")
    config_len = len(req.config_text or "")

    # Free tier: large config pastes (>8,000 chars) count as 3 queries to reflect
    # the higher token cost. The user is warned in the UI before submitting.
    query_weight = 3 if (tier == "free" and config_len > 8000) else 1

    # Check/increment query count via license server (atomic, weight-aware)
    check = _license_post("/query/check", {"token": token, "weight": query_weight})

    if not check.get("allowed", False):
        base_detail = check.get("detail", "Query limit reached.")
        if query_weight == 3:
            detail = (
                f"{base_detail} "
                f"This config paste ({config_len:,} chars) counted as 3 queries — "
                f"free tier charges 3 queries for configs over 8,000 characters. "
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

    conv_id    = get_or_create_conversation(req.conversation_id)
    db_history = load_conversation_history(conv_id)   # source of truth for memory
    messages   = build_messages(sanitized_req, db_history=db_history)
    client     = anthropic.Anthropic(api_key=api_key)

    # Resolve model:
    #   - Free tier is always Haiku (enforced here regardless of req.model)
    #   - Paid tiers: "auto" → route by complexity; explicit model → honour it
    if tier == "free":
        resolved_model = "claude-haiku-4-5-20251001"
    elif req.model == "auto":
        resolved_model = _select_model(req.message, req.config_text, tier=tier)
    else:
        resolved_model = req.model

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
            subprocess.Popen([str(tmp), "/SILENT", "/FORCECLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS"])

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
# PAN Copilot — Project Intelligence

## What This Project Is

PAN Copilot is an AI assistant for Palo Alto Networks (PAN-OS) engineers built by Jack Miller (CISO, ADK Cyber). It runs as a native-looking Windows desktop app — a PyInstaller `.exe` that spins up a local FastAPI server and opens Microsoft Edge in `--app` mode (no URL bar, no tabs — indistinguishable from a native window). All firewall config data stays on the user's machine; only chat queries go to Anthropic.

**Website:** [adkcyber.com/pan-copilot.html](https://adkcyber.com/pan-copilot.html)
**Downloads CDN:** Cloudflare R2 at `downloads.adkcyber.com`
**License server:** `https://pan-copilot.onrender.com`

---

## Repository Layout

```
PAN Copilot_APP/                  <- THE canonical repo (C:\Users\jmill\Downloads\PAN Copilot_APP)
├── local/                        <- Desktop app source (PyInstaller target)
│   ├── pan_copilot.py            <- Entry point: starts uvicorn + launches Edge
│   ├── app.py                    <- FastAPI backend (chat, auth, file upload, /api/shutdown)
│   ├── pan_copilot_desktop.html  <- Frontend UI (single-file, served by FastAPI)
│   ├── pan_copilot.spec          <- PyInstaller build spec
│   ├── installer.iss             <- Inno Setup installer script
│   ├── pan_copilot.ico           <- App icon (BMP DIB format — Inno Setup requirement)
│   ├── rthook_fix_streams.py     <- PyInstaller runtime hook: patches sys.stdout/stderr
│   ├── requirements.txt          <- anthropic, fastapi, uvicorn, httpx, pydantic
│   └── BUILD.md                  <- Local build instructions
├── license_server/               <- Lightweight auth + quota server (deployed to Render)
│   ├── app.py                    <- FastAPI: register, login, query counting, key delivery
│   └── requirements.txt
├── backend/                      <- Legacy cloud backend (FastAPI v2, SQLite auth)
│   └── main.py                   <- Older full-featured backend; kept for reference
├── make_ico.py                   <- Generates pan_copilot.ico using Pillow (BMP DIB format)
├── PAN_Copilot_Master_System_Prompt.md  <- Core IP — NOT committed (in .gitignore)
├── tasks/todo.md                 <- Active task tracking
├── .github/workflows/
│   └── build-release.yml         <- CI: build exe -> sign -> package zip+installer -> upload R2
├── DEPLOY.md                     <- Railway/Render deployment guide
└── CLOUDFLARE_R2_SETUP.md        <- R2 bucket + public URL setup guide
```

**Website repo:** `C:\Users\jmill\Downloads\ADKCYBER_SITE`
- `js/main.js` — dynamic download URL logic (`[data-pan-download]`, `[data-pan-installer]`, `[data-pan-zip]`)

---

## Architecture

```
User Machine
├── PAN Copilot.exe  (PyInstaller windowed bundle)
│   ├── pan_copilot.py  -> acquires Windows named mutex (single instance)
│   │                   -> starts uvicorn on random 127.0.0.1:<port>
│   │                   -> launches Edge --app mode
│   │                   -> delegation-aware wait (if Edge exits <5s = delegated to existing)
│   ├── app.py          -> FastAPI: /api/chat, /api/login, /api/register, /api/shutdown
│   └── pan_copilot_desktop.html  -> full chat UI, served at /
│
└── ~/.pan_copilot/
    ├── config.json        <- session token only (API key NEVER written to disk)
    └── conversations.db   <- SQLite chat history

ADK Cyber Cloud
├── pan-copilot.onrender.com  <- license server (auth, quota, key delivery)
└── downloads.adkcyber.com    <- Cloudflare R2 (exe, installer, version.json)
```

**Data flow:**
- Login/register: user machine -> license server only
- Chat: user machine -> api.anthropic.com directly (using ADK's key, held in memory only)
- Firewall configs: never leave the user's machine (go to Anthropic only, never ADK servers)

---

## Pricing Tiers

| Tier  | Queries       | Price     |
|-------|---------------|-----------|
| Free  | 10 / week     | $0        |
| Pro   | 1,000 / month | $20/mo    |
| MAX   | 2,500 / month | $50/mo    |
| Owner | Unlimited     | Internal  |

---

## Build & Release Pipeline

**Trigger:** `git tag v1.0.X && git push origin v1.0.X`

**GitHub Actions steps (`build-release.yml`):**
1. Checkout repo on `windows-latest`
2. Write `PAN_Copilot_Master_System_Prompt.md` from GitHub Secret `PAN_COPILOT_SYSTEM_PROMPT`
3. `pip install` deps + PyInstaller
4. `pyinstaller pan_copilot.spec --clean`
5. Sign `PAN Copilot.exe` with EV cert via `signtool` (cert from Secret `CODE_SIGNING_CERT_PFX`)
6. Build Inno Setup installer (`PAN_Copilot_Setup_vX.X.X.exe`) and sign it
7. Zip portable version (`PAN_Copilot_vX.X.X.zip`)
8. Upload both to R2 under `/releases/vX.X.X/`
9. Write `version.json` to R2 root with `download_url`, `installer_url`, `version`

**Required GitHub Secrets:**
- `CF_R2_ACCESS_KEY_ID` / `CF_R2_SECRET_ACCESS_KEY` / `CF_R2_ACCOUNT_ID` / `CF_R2_BUCKET`
- `PAN_COPILOT_SYSTEM_PROMPT`
- `CODE_SIGNING_CERT_PFX` / `CODE_SIGNING_CERT_PASSWORD`

---

## Critical Implementation Details

### Single Instance (Windows Mutex)
`pan_copilot.py` calls `_acquire_single_instance_lock()` on startup. Uses a Windows named mutex so only one server runs at a time. A second `.exe` launch detects the mutex and delegates to the existing Edge window instead of starting a new server.

### Delegation-Aware Server Lifetime
When Edge exits in under 5 seconds it delegated to an existing instance. The server stays alive (up to 60 min safety net) instead of dying immediately. The `beforeunload` handler in `pan_copilot_desktop.html` calls `POST /api/shutdown` via `navigator.sendBeacon()` when the tab actually closes, which sets `uvicorn_server.should_exit = True` cleanly.

### Edge `--app` Mode + Isolated Profile
Edge is launched with `--app=http://127.0.0.1:<port>` and `--user-data-dir=<tempdir>`. The temp dir forces an isolated Edge process — without it, Edge delegates to the user's existing session and the subprocess exits immediately.

### ICO File Format
`pan_copilot.ico` must use **BMP DIB format** (not PNG chunks). Inno Setup validates ICO files strictly and rejects PNG-based ICOs. Always regenerate with `python make_ico.py`. Do NOT use Pillow's built-in `.save(..., format='ICO')` — it produces corrupt output for Inno Setup. The `make_ico.py` script manually assembles the BMP DIB structure using `struct`.

### PyInstaller Windowed Build + uvicorn Crash Fix
Windowed PyInstaller builds set `sys.stdout = sys.stderr = None`. Uvicorn's logging formatter calls `.isatty()` and crashes during `uvicorn.Config(...)`. Fix is three-layered:
1. `rthook_fix_streams.py` — PyInstaller runtime hook redirects None streams to devnull before any import
2. `pan_copilot.py` startup — second check redirects None streams to devnull
3. `_safe_dictConfig` wrapper + `configure_logging = lambda self: None` — neutralizes uvicorn's logging setup entirely

### System Prompt Handling
`PAN_Copilot_Master_System_Prompt.md` is in `.gitignore` — **never committed to the repo**. In CI it is injected from the GitHub Secret `PAN_COPILOT_SYSTEM_PROMPT`. For local builds, manually place it in the repo root before running PyInstaller. `app.py` reads it at startup from `_base() / "PAN_Copilot_Master_System_Prompt.md"`.

### Website Download Buttons
`ADKCYBER_SITE/js/main.js` fetches `version.json` from R2 on every page load and sets:
- `[data-pan-download]` → installer `.exe` (primary — what most buttons use)
- `[data-pan-installer]` → installer `.exe` (explicit)
- `[data-pan-zip]` → zip (explicit)
- `[data-pan-version]` → version string label

---

## Known Issues & Past Fixes

| Issue | Root Cause | Fix | Version |
|---|---|---|---|
| ERR_CONNECTION_REFUSED on 2nd launch | Edge delegates to existing instance; server exits immediately | Delegation-aware wait + `/api/shutdown` endpoint | v1.0.22 |
| Server stays alive after tab close | No shutdown signal when user closes tab | `beforeunload` → `sendBeacon('/api/shutdown')` | v1.0.22 |
| Users downloading ZIP not installer | `main.js` set `[data-pan-download]` to `download_url` (zip) | Changed to prefer `installer_url` | v1.0.23 |
| Desktop shortcut unchecked by default | `Flags: unchecked` in installer.iss | Changed to `Flags: checkedonce` | v1.0.23 |
| Invalid ICO / Inno Setup build failure | Pillow's ICO writer uses PNG chunks | Rewrote `make_ico.py` with BMP DIB struct assembly | v1.0.21 |
| PyInstaller spec literal `\n` in datas | PowerShell `-replace` with single-quoted replacement wrote backtick-n as text | Use double-quoted replacement string | v1.0.20 |
| Windowed exe crashes on launch | `sys.stdout/stderr = None` + uvicorn `.isatty()` call | Three-layer fix: rthook + startup + dictConfig patch | v1.0.x |
| Bash edits silently lost | Bash sandbox mounts wrong Windows path | **Always use Edit/Write tool directly; never bash for file edits** | Ongoing |

---

## File Edit Rules (CRITICAL — do not violate)

- **NEVER use bash to edit project files.** The bash sandbox mounts Windows NTFS paths unreliably and writes are sometimes invisible to Windows git.
- **Always use the `Edit` or `Write` tools directly** on `C:\Users\jmill\Downloads\PAN Copilot_APP\...`
- **Git operations from bash:** verify mount path first (`/sessions/.../mnt/PAN Copilot_APP/`). If a `.git/index.lock` exists and can't be removed from bash, write a `.ps1` script for the user to run.
- **Correct bash mount path:** `/sessions/eloquent-busy-wozniak/mnt/PAN Copilot_APP/`

---

## Workflow Orchestration

### Plan First
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan — don't keep pushing
- Write specs upfront to reduce ambiguity

### Verification Before Done
- Never mark complete without proving it works
- After git push: confirm with `git log --oneline -3`
- Ask: "Would a staff engineer approve this?"

### Self-Improvement Loop
- After any correction: update `tasks/lessons.md` with the pattern
- Rules must be specific enough to prevent the same mistake

### Core Principles
- **Simplicity First** — minimal code impact, touch only what's necessary
- **No Laziness** — find root causes, no temporary fixes, senior developer standards
- **Autonomous** — fix bugs without hand-holding; point at errors and resolve them

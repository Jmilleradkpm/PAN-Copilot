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
5. Azure login via OIDC (federated credential `pan-copilot-main` on app `pan-copilot-github-actions`)
6. Sign `PAN Copilot.exe` via Azure Trusted Signing (`adkcyber-signing` account, `pan-copilot` cert profile)
7. Build Inno Setup installer (`PAN_Copilot_Setup_vX.X.X.exe`) and sign it the same way
8. Zip portable version (`PAN_Copilot_vX.X.X.zip`)
9. Upload both to R2 under `/releases/vX.X.X/`
10. Write `version.json` to R2 root with `download_url`, `installer_url`, `version`

**Triggering a release:** GitHub Actions → Build & Upload to R2 → Run workflow → enter version (e.g. `v1.0.32`)

**Required GitHub Secrets:**
- `CF_R2_ACCESS_KEY_ID` / `CF_R2_SECRET_ACCESS_KEY` / `CF_R2_ACCOUNT_ID` / `CF_R2_BUCKET`
- `PAN_COPILOT_SYSTEM_PROMPT`
- `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_SUBSCRIPTION_ID`

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

---

# Coding Standards & Development Methodology
# Source: Anthropic Official Prompting Best Practices + /wizard 8-Phase Methodology

## Role

You are a senior software architect. You read before you write, test before you
implement, and attack your own code before you commit. You do not rush. You do
not guess. You do not add anything that was not asked for.

---

## 1. Anti-Over-Engineering

Only make changes that are directly requested or clearly necessary.
Keep solutions simple and focused.

**Scope:** Don't add features, refactor code, or make "improvements" beyond what
was asked. A bug fix doesn't need surrounding code cleaned up. A simple feature
doesn't need extra configurability.

**Documentation:** Don't add docstrings, comments, or type annotations to code
you didn't change. Only add comments where the logic isn't self-evident.

**Defensive Coding:** Don't add error handling, fallbacks, or validation for
scenarios that can't happen. Trust internal code and framework guarantees.
Only validate at system boundaries (user input, external APIs).

**Abstractions:** Don't create helpers, utilities, or abstractions for one-time
operations. Don't design for hypothetical future requirements. The right amount
of complexity is the minimum needed for the current task.

---

## 2. No Hard-Coding or Test-Gaming

Write high-quality, general-purpose solutions using standard tools.
Do not create helper scripts or workarounds to accomplish tasks more efficiently.
Implement solutions that work correctly for all valid inputs, not just test cases.
Do not hard-code values or create solutions that only work for specific inputs.
Instead, implement the actual logic that solves the problem generally.

Tests verify correctness — they do not define the solution.
If a task is unreasonable or a test is incorrect, say so rather than working around it.
The solution must be robust, maintainable, and extendable.

---

## 3. No Hallucinating Code

Never speculate about code you have not opened. If the user references a specific
file, read the file before answering. Investigate and read relevant files BEFORE
answering questions about the codebase. Never make any claims about code before
investigating unless you are certain — give grounded, hallucination-free answers.

---

## 4. Reversibility & Safety

Consider the reversibility and potential impact of every action.
Take local, reversible actions freely (editing files, running tests).
For actions that are hard to reverse, affect shared systems, or could be
destructive, ask the user before proceeding.

Actions that require confirmation:
- Destructive operations: deleting files or branches, dropping tables, `rm -rf`
- Hard-to-reverse operations: `git push --force`, `git reset --hard`, amending published commits
- Operations visible to others: pushing code, commenting on PRs, sending messages,
  modifying shared infrastructure

Do not use destructive actions as shortcuts when encountering obstacles.
Do not bypass safety checks (e.g., `--no-verify`) or discard in-progress work.

---

## 5. Default to Action, Not Suggestion

Implement changes rather than only suggesting them. If the user's intent is clear,
use tools to discover any missing details instead of asking. If the user's intent
is ambiguous on a potentially destructive action, ask once — clearly and briefly.

For exploratory or research tasks, provide information and recommendations first,
then ask if implementation is desired.

---

## 6. Parallel Tool Use

If you intend to call multiple tools and there are no dependencies between them,
make all independent calls in parallel. When reading multiple files, read them
simultaneously. Maximize parallel tool calls to increase speed and efficiency.
Never use placeholders or guess missing parameters in tool calls.

---

## 7. Context Management

Track context usage. As the context window fills, performance degrades.
Use `/clear` between unrelated tasks. When approaching context limits, save
progress and state before the context window refreshes. Prioritize completing
components fully before moving to the next. Do not stop tasks early due to
token budget concerns — save state and continue from where you left off.

---

## 8. /wizard — 8-Phase Development Methodology

Activate with `/wizard <task or GH issue>` in Claude Code.
Use for: complex tasks, multi-file changes, architectural decisions, any task
where "it works" is not the same as "it's correct."

### Phase 1 — Plan Before You Touch Anything

Read CLAUDE.md. Find the linked GitHub issue (or create one with acceptance
criteria). Assess complexity: files affected, architectural impact, risk surface.
Build a scoped todo list. Do not write code yet.

### Phase 2 — Explore Before You Assume

Grep for every model, method, relationship, constant, and enum you intend to
use. Verify they exist before referencing them. Check git history for recent
renames. Confirm the database schema matches your assumptions.
No hallucinated method chains. No invented APIs.

### Phase 3 — Write Tests First (TDD, No Exceptions)

Write failing tests before implementation. Run them — they must fail.
Use mutation-resistant assertions. Assert every side effect: timestamps set,
notifications sent, counters incremented. Tests should be skeptics, not rubber stamps.

### Phase 4 — Implement the Minimum

Write only the code required to make the tests pass. Follow existing patterns.
No scope creep. No clever abstractions. No gold-plating. Scope creep is a bug.

### Phase 5 — Verify Zero Regressions

Run the full related test suite, not just the new tests. Fix any regressions
before proceeding. Do not move forward with a broken suite.

### Phase 6 — Document While Context Is Fresh

Add inline comments only where logic isn't self-evident. Update the changelog.
Update any docs that reference changed behavior. Do this now — not later.

### Phase 7 — Adversarial Self-Review

Before every commit, review your own work as an attacker, not as the author.
Run through this checklist every time:

- What happens if this runs twice concurrently?
- What if the input is null? Empty? Negative? Extremely large?
- What assumptions am I making that could be wrong in production?
- Are there race conditions if two requests hit this simultaneously?
- Is any string hard-coded that should use a constant or enum?
- Is any nullable field called without a null check?
- Would I be embarrassed if this broke on day one in production?

Fix everything found before proceeding.

### Phase 8 — Quality Gate Cycle

Open the PR. Monitor your automated review bot (CodeRabbit, Bug Bot, etc.).
Read every finding. Fix valid issues. Reply to false positives with reasoning.
Repeat until the bot status is clean. No unresolved findings ship.

---

## 9. Living Rules — Self-Updating on Mistakes

When you make a mistake that isn't covered by the rules above, and the user
corrects you, update this CLAUDE.md file with a new rule so the mistake doesn't
happen again. Rules earned from real mistakes are the most valuable ones.

Only add a rule if Claude would make the mistake without it. If Claude already
does something correctly, the rule is noise. Every unnecessary rule dilutes the
ones that matter.

---

## Stack & Commands

**Language / Framework:** Python 3.12 / FastAPI + PyInstaller (desktop exe); Vanilla JS (frontend, no framework)

**Run locally:** `cd local && python pan_copilot.py`

**License server (local):** `cd license_server && uvicorn app:app --reload --port 8001`

**Build exe:** `cd local && pyinstaller pan_copilot.spec --clean`

**Release trigger:** GitHub Actions → "Build & Upload to R2" → Run workflow → enter version (e.g. `v1.0.70`)

**Key directories:**
- `local/` — desktop app source (FastAPI backend + HTML frontend + KB files)
- `local/kb/` — markdown knowledge base files (KB-*.md)
- `license_server/` — auth + quota server (deployed to Render)
- `.github/workflows/` — CI/CD (build, sign, upload to R2)
- `backend/` — legacy reference backend (do not ship)

**Conventions:**
- Python: snake_case, Pydantic models for all API request/response boundaries
- JavaScript: camelCase, `const`/`let` only, async/await over `.then()`
- All new API endpoints validated with Pydantic — never raw `request.json()`
- KB trigger maps live in `_KB_TRIGGER_MAP` dict in `local/app.py`

---

## Branch & Commit Rules

- One feature or fix per commit/tag
- Version tags: `v1.0.X` — increment patch for every release
- Commit message format: imperative present tense, e.g. `Add weighted query deduction for free tier`
- Never force-push to main
- Always confirm with `git log --oneline -3` after pushing
- `PAN_Copilot_Master_System_Prompt.md` is in `.gitignore` — **never commit it**

---

## Known Gotchas

- **ICO format:** `pan_copilot.ico` must be BMP DIB (not PNG chunks). Always regenerate with `python make_ico.py`. Pillow's built-in ICO writer produces corrupt output for Inno Setup.
- **PyInstaller windowed + uvicorn:** `sys.stdout/stderr = None` in windowed builds crashes uvicorn's `.isatty()` call. Three-layer fix already in place — do not remove `rthook_fix_streams.py` or the `_safe_dictConfig` wrapper.
- **Bash edits silently lost:** Never use bash to edit project files. Always use the `Edit`/`Write` tools directly. Bash sandbox mounts NTFS paths unreliably.
- **Python path in Git Bash:** `/c/Users/...` form fails; use `'C:/Users/...'` Windows-style paths.
- **System prompt:** `PAN_Copilot_Master_System_Prompt.md` must exist at repo root for local builds. In CI it is injected from the `PAN_COPILOT_SYSTEM_PROMPT` GitHub Secret.
- **Edge isolation:** Edge must be launched with `--user-data-dir=<tempdir>`. Without it, Edge delegates to the user's existing session and the subprocess exits immediately, triggering the delegation-aware wait incorrectly.
- **Free tier model lock:** Free tier is hard-locked to `claude-haiku-4-5-20251001` in `_select_model()`. Do not allow `req.model` overrides to bypass this for free users.
- **Weighted query deduction:** Large config pastes (>8,000 chars) on free tier cost 3 queries. The `weight` parameter is sent to `/query/check` on the license server — the atomic SQL deducts the full weight in one statement to prevent TOCTOU races.

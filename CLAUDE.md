# PAN Copilot — Project Intelligence

> Project-specific guidance for AI coding agents. Personal/cross-project
> rules live in the contributor's own `~/.claude/CLAUDE.md` and are loaded
> automatically — they don't belong here.

## What This Project Is

ADK Cyber AI (internal name "PAN Copilot") is an AI assistant for Palo Alto
Networks engineers, shipped by Adirondack CyberSecurity. It runs as a native
Windows desktop app (.NET 8 + WPF + WebView2) that talks to Anthropic for chat
and to optional LM Studio / Ollama for local-LLM mode. Firewall configs stay
on the user's machine; only chat queries cross the wire, and only to Anthropic.

- **Public brand:** "ADK Cyber AI"
- **Website:** [adkcyber.com/upgrade.html](https://adkcyber.com/upgrade.html) (`pan-copilot.html` redirects)
- **Downloads CDN:** Cloudflare R2 at `https://downloads.adkcyber.com/`
- **License server:** [pan-copilot.onrender.com](https://pan-copilot.onrender.com) (Render-hosted FastAPI)
- **Current release:** v3.8 (portable zip, banner-driven auto-update)

---

## Repository Layout

```
PAN-Copilot/
├── dotnet/                     <- The shipping app (.NET 8 + WPF + WebView2)
│   ├── PanCopilot.csproj
│   ├── App.xaml / MainWindow.xaml(.cs)
│   ├── Services/               <- Backend services (anthropic, license, KB, etc.)
│   │   ├── AnthropicClient.cs        — raw HTTPS+SSE, no SDK (escapes jiter.pyd AV trigger)
│   │   ├── ApiRouter.cs              — virtual REST: every old /api/* path
│   │   ├── ChatService.cs            — quota, redaction, model routing, SSE
│   │   ├── KbService.cs              — local KB short-circuit (11 articles)
│   │   ├── LicenseClient.cs          — auth + quota against license_server
│   │   ├── LocalLlmService.cs        — OpenAI-compatible local servers + auto-detect
│   │   ├── ShortcutService.cs        — first-run Desktop + Start Menu shortcuts
│   │   ├── SystemPromptLoader.cs     — decrypts the AES-GCM embedded prompt blob
│   │   ├── UpdateService.cs          — zip-based banner auto-update
│   │   └── Migration/                — full multi-vendor firewall config migrator
│   ├── Bridge/PanCopilotHost.cs      — JS↔C# bridge (AddHostObjectToScript)
│   ├── Frontend/
│   │   ├── index.html                — ported pan_copilot_desktop.html + fetch shim
│   │   └── kb/                       — 11 markdown KB articles + kb_triggers.json
│   ├── PanCopilot.Tests/             — 60+ xUnit tests
│   └── installer.iss                 — KEPT for reference; no longer used in CI
│
├── local/                      <- LEGACY v2 Python app — historical reference only
├── license_server/             <- Render-hosted FastAPI (auth, quota, key delivery)
├── backend/                    <- LEGACY cloud backend — historical reference only
└── .github/workflows/
    ├── build-release.yml             — LEGACY Python release (do not trigger)
    └── build-release-dotnet.yml      — ACTIVE .NET release (trigger this for v3.X)
```

**Website repo (separate):** `ADKCYBER_SITE` — Netlify-hosted, auto-deploys on
push to main. Download buttons read `version.json` from R2 and prefer
`download_url` (zip) for v3.X.

---

## Architecture

```
User Machine
├── PAN Copilot.exe  (self-contained single-file .NET 8)
│   ├── MainWindow.xaml.cs   -> wires services, navigates WebView2 to Frontend/index.html
│   ├── WebView2             -> renders ported HTML/JS UI
│   ├── PanCopilotHost       -> exposes Api(method,path,body) + StreamChat to JS
│   ├── ApiRouter            -> dispatches /api/* virtual REST to services
│   └── Services/*           -> chat, KB, license, local-LLM, updates, shortcuts
│
└── %USERPROFILE%\.pan_copilot\
    ├── settings_v3.json        <- DPAPI-wrapped session token + firewall key
    ├── conversations_v3\       <- per-conversation JSON history
    └── advisories_cache.json   <- PAN RSS cache

ADK Cyber Cloud
├── pan-copilot.onrender.com    <- license server
└── downloads.adkcyber.com      <- R2: version.json + releases/v3.X/*.zip
```

- Anthropic: direct over raw HTTPS + SSE (`Services/AnthropicClient.cs`) — no
  Python SDK, no `jiter`, no behavioral AV trigger
- License server: only used for auth + quota; never receives configs
- WebView2 user-data folder: pinned to `%LOCALAPPDATA%\ADK Cyber AI\WebView2\`
  (Program Files default crashes standard users with `E_ACCESSDENIED`)

---

## Pricing Tiers

| Tier  | Queries       | Price     |
|-------|---------------|-----------|
| Free  | 10 / week     | $0        |
| Pro   | 1,000 / month | $20 / mo  |
| MAX   | 2,500 / month | $50 / mo  |
| Owner | Unlimited     | Internal  |

Free tier is hard-locked to `claude-haiku-4-5-20251001`. Large config pastes
(>8,000 chars) on free tier cost 3 queries via an atomic SQL deduction in
the license server.

---

## Build & Release

**Distribution model:** portable zip (extracts to `%LOCALAPPDATA%\Programs\ADK Cyber AI\`).
Inno Setup installer was dropped after v3.4 because Bitdefender ATC flagged
installer behavior itself (`unins000.exe`, `setup.tmp`, `is-*.tmp\` staging)
regardless of code-signing. The MSIX / Microsoft Store submission is the
planned permanent home.

**Trigger:** GitHub Actions → "Build & Release (.NET)" → Run workflow →
`version: v3.X` (must be > current `version.json` on R2).

Workflow does, in order:
1. Inject system prompt from `PAN_COPILOT_SYSTEM_PROMPT` secret
2. AES-256-GCM encrypt it (key from `PAN_COPILOT_PROMPT_AES_KEY` secret) into
   `Services/system_prompt.bin`, generate `Services/PromptKey.cs`, delete plaintext
3. `dotnet restore` + `dotnet test` (must pass — currently 60 tests)
4. Inject `<Version>` into `PanCopilot.csproj`
5. `dotnet publish -r win-x64 --self-contained /p:PublishSingleFile=true`
6. Sanity check: aborts if any `*System_Prompt*` file leaks into `publish/`
7. Azure OIDC login → Trusted Signing on `PAN Copilot.exe`
8. Zip + SHA-256 → upload to R2
9. Overwrite `version.json` at the bucket root — **this flips the live update
   pointer; every v3.X+ client's next banner poll picks up the new version**

**Required secrets:** `PAN_COPILOT_SYSTEM_PROMPT`, `PAN_COPILOT_PROMPT_AES_KEY`,
`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_SUBSCRIPTION_ID`, `CF_R2_ACCESS_KEY_ID`,
`CF_R2_SECRET_ACCESS_KEY`, `CF_R2_ACCOUNT_ID`, `CF_R2_BUCKET`.

---

## Critical Implementation Details

### System prompt encryption
- The master prompt is AES-256-GCM encrypted by the CI step into an embedded
  resource (`PanCopilot.Services.system_prompt.bin`). The per-build key is a
  compiled const in `Services/PromptKey.cs` generated from
  `PAN_COPILOT_PROMPT_AES_KEY`. `SystemPromptLoader.Load()` decrypts in
  memory at startup — **plaintext never touches disk**.
- Wire format: `nonce(12) || ciphertext(N) || tag(16)`.
- Dev: leave `PromptKey.KeyB64 = ""` and drop a plaintext
  `PAN_Copilot_Master_System_Prompt.md` next to the exe; the loader falls
  back to it. Never commit either the real key or the plaintext.

### Auto-update (banner-driven, portable zip)
- Frontend polls `/api/version` once on `init()` and every 30 min thereafter
  (`setInterval`). The banner shows when `update_available: true`.
- Click → `/api/update` → `UpdateService.InstallUpdateAsync`:
  download zip → SHA-256 vs `zip_sha256` from manifest → extract to staging
  → Authenticode verify (signer must contain "Adirondack CyberSecurity") →
  write `%TEMP%\adk_update_<ver>.ps1` helper → exit. Helper waits for the
  PID to drop, copies staged files over the install dir, relaunches.
- `MainWindow.exitApp` defers `Application.Current.Shutdown()` ~1.5s on a
  `Task.Run` so the `/api/update` response can flush before the bridge tears
  down — otherwise the banner shows "Download failed" on success.

### WebView2 user-data folder
- Default location is next-to-the-exe. Standard users can't write to
  `C:\Program Files\...`, so install-to-Program-Files installs crash with
  `E_ACCESSDENIED` at first launch. Always pin via
  `CoreWebView2Environment.CreateAsync(null, userDataFolder, null)` where
  `userDataFolder = %LOCALAPPDATA%\ADK Cyber AI\WebView2`.

### Local-LLM auto-detect
- `LocalLlmService.DetectAsync` probes `localhost:1234` (LM Studio) and
  `localhost:11434` (Ollama) in parallel with a 2-second timeout. First
  hit wins. `PickDefaultModel` filters embeddings and picks alphabetical.
- Frontend `tryAutoDetectLocalLlm()` runs from `init()` only when the URL
  is empty OR still the shipped `11434` default with no model picked.

### KB short-circuit
- `KbService` matches the user message against `Frontend/kb/kb_triggers.json`
  (extracted from the v2 Python `_KB_TRIGGER_MAP` so the two builds stay in
  lockstep). A direct KB-ID query (`kb-pan-dec-001`) always returns the full
  article; other queries go through the section-relevance scorer.

### First-run shortcuts
- `ShortcutService.EnsureFirstRunShortcuts()` drops a Desktop + Start Menu
  `.lnk` via `WScript.Shell` COM (a normal Windows Script Host call —
  not behavioral-AV-flagged). Marker file at
  `%LOCALAPPDATA%\ADK Cyber AI\.shortcuts_attempted` prevents re-creation.

### Website download buttons
- `ADKCYBER_SITE/js/main.js` reads `version.json` on every page load.
  `[data-pan-download]` and `[data-pan-zip]` both prefer `download_url`
  (the zip) for v3.X+. The legacy `[data-pan-installer]` still reads
  `installer_url` for any pre-v3.5 client; harmless but unused.

---

## Known Gotchas

| Gotcha | Why it bites | Fix |
|---|---|---|
| Authenticode signer string is `Adirondack CyberSecurity`, NOT `ADK Cyber` | Marketing name vs legal entity on the Azure Trusted Signing cert. Mismatched check brick'd v2.0 auto-update. | Verify against `Adirondack CyberSecurity`. Env override: `PAN_COPILOT_EXPECTED_SIGNER`. |
| PowerShell here-strings inside YAML `run: \|` | Closing `'@` must be column-0, which clashes with YAML literal-block indentation. GitHub rejects the workflow with "Workflow does not have 'workflow_dispatch' trigger". | Use `$lines = @('...', '...'); Set-Content -Value $lines`. |
| `git commit -a` skips NEW files | Only stages MODIFIED tracked files. New `.cs` files referenced from a committed `MainWindow.xaml.cs` will break CI with `CS0103: The name 'X' does not exist`. | `git add -A` before commit, ALWAYS, in mirror/clone-and-push flows. |
| Producer/consumer mismatch on version-info | InstallUpdateAsync read `download_url` from a cache GetVersionInfoAsync never wrote it into. Both halves' unit tests passed; the chain didn't. | When adding a field, grep both writer and reader. Add an end-to-end test. |
| Bitdefender ATC flags Inno Setup installer activity | Behavioral heuristic on `setup.tmp` / `unins000.exe` / `.lnk` creation, regardless of code-signing. | Portable zip distribution. Threat-name exclusion `Atc4.Detection` for jmill's own machine only. |
| `Application.Current.Shutdown()` inside an HTTP await chain | Synchronously tears down the dispatcher before the response can flush. Frontend reports "Download failed" on a successful update. | Defer via `Task.Run` with a small delay; let the bridge serialize first. |

---

## Branch & Commit Rules

- Conventional Commits. One feature/fix per commit.
- Releases are version inputs to the workflow, not git tags. Don't infer the
  next version from `git tag` — the real version is whatever you pass to the
  dispatch and what currently lives on R2 (`version.json`).
- Never force-push to `main`.
- Never commit `PAN_Copilot_Master_System_Prompt.md`, `Services/system_prompt.bin`,
  or a populated `Services/PromptKey.cs`. All three are in `.gitignore`; CI
  writes them at build time.
- After pushing, `git show --stat --name-only HEAD` should list every file the
  change touches; missing `.cs` will break CI.

---

## Things NOT To Do

- Don't ship a release without bumping `<Version>` (CI does it; never inject manually).
- Don't reintroduce the Inno Setup installer — Bitdefender will flag it on every customer.
- Don't ship the system prompt as plaintext. There's a CI sanity check that
  aborts the release if a `*System_Prompt*` file lands in `publish/`.
- Don't hardcode the signer string anywhere except `UpdateService.ExpectedSigner`
  (which already reads the env var override).
- Don't use the Python SDK for Anthropic — `jiter.cp312-win_amd64.pyd` is the
  binary Bitdefender flagged. `AnthropicClient.cs` is raw HTTPS+SSE for a reason.
- Don't run a release workflow while another is in progress (the workflow
  overwrites `version.json` non-atomically).

---

*Lessons learned across releases live in the contributor's own*
*`~/.claude/projects/.../memory/` directory — see the `feedback_*` files there*
*for the full debugging history (rushed-release cascade, here-strings vs YAML,*
*git commit -a, etc.). This file captures what the project IS today;*
*memory captures what we learned getting it here.*

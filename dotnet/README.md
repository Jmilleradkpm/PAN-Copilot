# PAN Copilot (.NET) — v3 rewrite POC

Native Windows rewrite of ADK Cyber AI in **.NET 8 + WPF + WebView2**, designed
to eliminate the antivirus-false-positive problem that the PyInstaller +
Anthropic Python SDK build hit (`jiter.cp312-win_amd64.pyd` etc. being flagged
as `Atc4.Detection` by Bitdefender ATC, blocking installs for every customer).

## Why this exists

The Python build's `jiter.pyd` + httptools `.pyd` + PyInstaller bootloader
combo trips behavioral AV scanners. There is no per-customer fix that scales.
This rewrite eliminates the trigger by replacing the Python runtime + the
Anthropic SDK with:

- **C# + System.Net.Http** — Anthropic Messages API called directly via SSE.
  No SDK, no jiter, no .pyd files of any kind.
- **WPF + WebView2** — hosts the existing HTML/JS frontend. Microsoft-signed
  DLLs that Defender trusts by default.
- **MSIX packaging (planned)** — distribute via the Microsoft Store for
  implicit Defender trust.

## Current state (proof-of-concept)

| | Value |
|---|---|
| Build size | ~2 MB |
| `.pyd` files in output | 0 |
| Anthropic SDK dependency | none |
| WebView2 runtime required | yes (ships with Edge Chromium on Windows 10/11) |
| .NET runtime required | .NET 8 desktop (~50 MB shared install) — or self-contained for ~70 MB single bundle |

The POC ships chat streaming end-to-end. The migration engine, panos client,
checks engine, advisories, and license-server integration are all still in the
Python repo and will be ported in phases.

## Run

```powershell
# Install .NET 8 SDK once
winget install --id Microsoft.DotNet.SDK.8

# Set the API key (POC reads from env; production pulls from license server)
$env:ANTHROPIC_API_KEY = "sk-ant-..."

# Build + run
cd PAN-Copilot-dotnet
dotnet run
```

## Build a release artifact

```powershell
dotnet publish -c Release -r win-x64 --self-contained false
# Output: bin/Release/net8.0-windows/win-x64/publish/PAN Copilot.exe
```

For a self-contained single-file bundle (no .NET runtime install needed on
target machine):

```powershell
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true
```

## Architecture

```
MainWindow.xaml          WPF window hosting WebView2
MainWindow.xaml.cs       Wires up the WebView2, host bridge, frontend nav
Frontend/index.html      Chat UI (will absorb the existing pan_copilot_desktop.html)
Services/AnthropicClient Direct HTTPS + SSE streaming to api.anthropic.com
Bridge/PanCopilotHost    COM-visible host object exposed to JS via
                         chrome.webview.hostObjects.host
```

JS calls `await host.StreamChat(payload)`; C# streams deltas back to JS via
`WebView.CoreWebView2.PostWebMessageAsString`, which the page listens for and
renders into the bubble. No HTTP server, no localhost port — pure in-process
host bridge.

## Porting status

**Ported, compiling, and tested (22 xUnit tests passing):**
- [x] WPF + WebView2 host + JS↔C# bridge (no localhost HTTP server)
- [x] Chat streaming via raw HTTPS + SSE (`AnthropicClient`) — no SDK, no jiter
- [x] License client: `/auth/login|register|validate`, `/query/check`
  (`LicenseClient`)
- [x] Encrypted key delivery: HKDF + Fernet decrypt in C# (`Fernet`)
- [x] Read-only PAN-OS/Panorama client: keygen, op, get_config, system_info
  (`PanosClient`)
- [x] `test` command builder (security/nat policy match, fib-lookup)
  (`TestCommandBuilder`)
- [x] Config hygiene engine: any-any / no-profiles / no-logging / service-any /
  disabled / shadowed (`ChecksEngine`)
- [x] Credential redaction before sending to Anthropic (`ConfigSanitizer`)
- [x] Settings + DPAPI-wrapped session token & firewall key (`SettingsStore`)
- [x] Functional multi-panel UI: Chat, Firewall, Config Hygiene, Account
- [x] GitHub Actions: build → test → publish self-contained → Azure-sign →
  hash → upload to R2 (`.github/workflows/build-release.yml`)

**Not yet ported (remaining work, in rough effort order):**
- [ ] **Migration engine** — the multi-vendor (ASA/Checkpoint/Fortinet/Juniper)
  → PAN-OS converter. This is the single largest module; it needs a faithful
  port of each vendor parser + the IR + emitters and was intentionally NOT
  stubbed/faked here. ~1–2 weeks on its own.
- [ ] Conversation persistence (SQLite history) — Python build used a local DB
- [ ] KB trigger system + bundled KB articles
- [ ] Security-advisory poller (PAN RSS) + version-aware "am I affected?"
- [ ] Local-LLM provider (Ollama / LM Studio) path
- [ ] Full visual parity with `pan_copilot_desktop.html` (the new UI is clean
  and functional but not yet a pixel match — port the styled markup into
  `Frontend/`)
- [x] MSIX packaging scaffold (`packaging/ADKCyberAI.Package.wapproj`, Store build
  workflow `.github/workflows/build-msix.yml`, Store updater gated)
- [ ] Microsoft Store submission (paste Partner Center identity into
  `packaging/PartnerCenter.Identity.props`, download MSIX from **Build MSIX (Store)**
  workflow artifact, upload to package flight)
- [ ] Auto-update client (download + verify + apply), matching v2.1's
  signature/hash checks

The **architecture is in place** for all of the above: new backend logic is a
C# service in `Services/` exposed via one method on `PanCopilotHost`, and new UI
is a panel in `Frontend/index.html`.

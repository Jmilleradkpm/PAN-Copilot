# ADK Cyber AI — Mac & iOS (.NET MAUI)

Second edition of PAN Copilot for **Mac Catalyst** and **iOS**, sharing the same backend and web UI as the Windows app.

## Layout

```
dotnet/
├── PanCopilot.csproj          # Windows (WPF + WebView2) — unchanged UX
├── PanCopilot.Core/           # Shared services (chat, KB, license, migration, …)
├── PanCopilot.Apple/          # MAUI shell: localhost API + WebView
└── Frontend/                # Shared HTML/JS UI + KB articles
```

## Architecture

| Windows | Mac / iOS |
|---------|-----------|
| WebView2 + `PanCopilotHost` bridge | Embedded Kestrel on `127.0.0.1` + MAUI `WebView` |
| DPAPI secrets | Keychain via `SecureStorage` + AES-GCM |
| R2 zip auto-update | App Store updates (`distribution_channel: appstore`) |

The Apple app starts a localhost HTTP server (`LocalApiServer`) that exposes the same `/api/*`, `/chat/stream`, and `/health` routes as the Windows virtual REST router. The existing `Frontend/index.html` fetch shim falls back to real HTTP when the WebView2 bridge is absent.

## Prerequisites

- macOS 14+ with Xcode 15+
- .NET 8 SDK + MAUI workload:

```bash
dotnet workload install maui
```

## Local build

```bash
cd dotnet
dotnet restore PanCopilot.sln

# Mac app (.app / .pkg)
dotnet build PanCopilot.Apple/PanCopilot.Apple.csproj -f net8.0-maccatalyst -c Debug

# iOS simulator
dotnet build PanCopilot.Apple/PanCopilot.Apple.csproj -f net8.0-ios -c Debug
```

For local dev without CI secrets, place `PAN_Copilot_Master_System_Prompt.md` in `dotnet/` (plaintext fallback).

## CI

GitHub Actions: **Build Apple (.NET MAUI)** (`build-release-apple.yml`) — manual `workflow_dispatch`, runs on `macos-14`, uploads Mac Catalyst + iOS artifacts.

## App Store (not yet wired)

- **Bundle ID:** `com.adkcyber.pancopilot`
- Mac Catalyst: distribute `.pkg` via Mac App Store or notarized direct download
- iOS: archive + upload via Xcode / Transporter

Add signing certificates and provisioning profiles to the workflow before shipping to production.

## Platform notes

- **Local LLM:** LM Studio/Ollama on Mac use the same ports as Windows; iOS cannot reach `localhost` LLM on a desktop — use cloud chat on iPhone/iPad.
- **Firewall API:** Read-only PAN-OS XML API works from all platforms when the firewall is reachable on the network.
- **Updates:** In-app R2 zip updater is disabled on Apple (`UpdateService` returns store-managed version info).
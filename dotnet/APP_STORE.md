# ADK Cyber AI — Mac & iOS App Store Submission

Bundle ID: **`com.adkcyber.pancopilot`**  
App name: **ADK Cyber AI**  
Company: **Adirondack CyberSecurity**

This guide walks through App Store Connect setup, signing, building, and uploading both the **Mac App Store** (Mac Catalyst) and **iOS App Store** builds from the shared `PanCopilot.Apple` MAUI project.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Apple Developer Program | $99/year — [developer.apple.com](https://developer.apple.com) |
| Mac with Xcode 15+ | You have Xcode 26.6 installed |
| .NET 8 + MAUI | `dotnet workload install maui` |
| Encrypted system prompt | Production builds need `system_prompt.bin` + `PromptKey.cs` (see CI workflow) |

**Current machine status:** run `security find-identity -v -p codesigning` — you need at least one **Apple Distribution** identity before uploading.

---

## Phase 1 — Apple Developer Portal

### 1.1 Register the App ID

1. [Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources/identifiers/list) → **Identifiers** → **+**
2. Type: **App IDs** → **App**
3. Description: `ADK Cyber AI`
4. Bundle ID: **Explicit** → `com.adkcyber.pancopilot`
5. Capabilities: enable **App Groups** only if needed later; default is fine
6. Register

### 1.2 Create distribution certificates

In Xcode (easiest):

1. **Xcode → Settings → Accounts** → add your Apple Developer Apple ID
2. Select your team → **Manage Certificates…**
3. Create **Apple Distribution** (and **Developer ID Application** if you ever ship direct-download Mac builds)

Or create manually in the Developer portal under **Certificates**.

### 1.3 Provisioning profiles

Create **two** App Store distribution profiles:

| Profile | Type | App ID |
|---------|------|--------|
| `ADK Cyber AI Mac App Store` | **Mac App Store Connect** (Mac Catalyst) | `com.adkcyber.pancopilot` |
| `ADK Cyber AI iOS App Store` | **App Store Connect** (iOS) | `com.adkcyber.pancopilot` |

Download both `.provisionprofile` files and double-click to install (or drag into Xcode).

---

## Phase 2 — App Store Connect

### 2.1 Create the app record

1. [App Store Connect](https://appstoreconnect.apple.com) → **Apps** → **+** → **New App**
2. Platforms: check **iOS** and **macOS** (single listing for Catalyst + iOS)
3. Name: **ADK Cyber AI**
4. Primary language: English (U.S.)
5. Bundle ID: `com.adkcyber.pancopilot`
6. SKU: `adk-cyber-ai` (any unique string)
7. User access: Full access

### 2.2 App Information

| Field | Suggested value |
|-------|-----------------|
| Category (primary) | Developer Tools |
| Category (secondary) | Productivity |
| Content rights | Does not contain third-party content (unless using Palo Alto trademarks in screenshots — use original UI only) |
| Age rating | Complete questionnaire (no violence; AI chat → likely 4+) |

### 2.3 Pricing & availability

- Free app with **in-app purchases** handled externally (Lemon Squeezy links in app — same as Windows Store policy approach)
- Or paid upfront — match your business model
- Availability: all territories or US-first

### 2.4 Privacy

**App Privacy questionnaire** (App Store Connect → App Privacy):

| Data type | Collected? | Purpose |
|-----------|------------|---------|
| Email address | Yes | Account / authentication |
| User ID | Yes | License session token |
| Usage data | Yes | Query quota tracking |
| Credentials in configs | No (redacted on device before transmission) |

Privacy policy URL: `https://www.adkcyber.com/adk-cyber-ai.html#privacy`

**Encryption:** `ITSAppUsesNonExemptEncryption = false` is set in Info.plist (HTTPS only). In App Store Connect, answer **No** to custom encryption export compliance.

### 2.5 Screenshots & metadata (per platform)

Prepare for **iPhone 6.7"**, **iPad 12.9"**, and **Mac** (1280×800 or 1440×900):

- Login screen
- Chat with PAN-OS question
- Product dropdown (iOS)
- KB article response
- Account panel

Description highlights: local KB articles, credential redaction, cloud AI via ADK gateway, PAN-OS/Cortex/Prisma focus.

### 2.6 Review notes

Include for Apple reviewers:

```
Test account:
  Email: reviewer@adkcyber.com  (create a dedicated reviewer account)
  Password: <provide in App Review Information>

The app requires sign-in to an ADK Cyber account. Cloud AI queries route through
our license server at https://pan-copilot.onrender.com. Local KB articles work
offline without quota. iOS uses cloud chat only (no on-device LLM).
```

Create a real reviewer account on your license server before submission.

---

## Phase 3 — Build & upload

### 3.1 Set environment variables

```bash
export APPLE_TEAM_ID="XXXXXXXXXX"          # 10-char Team ID
export APPLE_CODESIGN_KEY="Apple Distribution: Adirondack CyberSecurity (XXXXXXXXXX)"
export APPLE_CODESIGN_PROVISION_MAC="ADK Cyber AI Mac App Store"
export APPLE_CODESIGN_PROVISION_IOS="ADK Cyber AI iOS App Store"
```

Find Team ID: Developer portal → Membership, or `xcodebuild -showBuildSettings | grep DEVELOPMENT_TEAM`.

### 3.2 Production build (encrypted prompt)

For store builds, encrypt the system prompt the same way CI does (`build-release-apple.yml` step **Encrypt system prompt**). GitHub secrets:

- `PAN_COPILOT_SYSTEM_PROMPT`
- `PAN_COPILOT_PROMPT_AES_KEY`

### 3.3 Run the build script

```bash
cd dotnet
chmod +x scripts/build-appstore-apple.sh
./scripts/build-appstore-apple.sh 3.20
```

Outputs:

| Platform | Artifact | Upload via |
|----------|----------|------------|
| Mac App Store | `publish/appstore/maccatalyst/*.pkg` | Transporter or `xcrun altool` |
| iOS App Store | `publish/appstore/ios/*.ipa` | Transporter or Xcode Organizer |

### 3.4 Upload with Transporter

1. Install **Transporter** from the Mac App Store
2. Drag the `.ipa` and `.pkg` files into Transporter
3. Sign in with your App Store Connect Apple ID
4. Deliver

### 3.5 Attach builds in App Store Connect

1. App → **TestFlight** tab — confirm builds process (10–30 min)
2. App → **macOS** / **iOS** version → **Build** → select uploaded build
3. Submit for review

---

## Phase 4 — CI (GitHub Actions)

Workflow: `.github/workflows/build-release-apple.yml`

Add these GitHub repository secrets before running a signed release:

| Secret | Purpose |
|--------|---------|
| `PAN_COPILOT_SYSTEM_PROMPT` | Encrypted prompt source |
| `PAN_COPILOT_PROMPT_AES_KEY` | AES key (base64) |
| `APPLE_TEAM_ID` | Team ID |
| `APPLE_CODESIGN_KEY` | Distribution cert name |
| `APPLE_CODESIGN_PROVISION_MAC` | Mac profile name |
| `APPLE_CODESIGN_PROVISION_IOS` | iOS profile name |
| `APPLE_CERTIFICATE_P12` | Base64 .p12 (optional for CI) |
| `APPLE_CERTIFICATE_PASSWORD` | .p12 password |

Run: **Actions → Build Apple (.NET MAUI) → Run workflow** with version `v3.20`.

---

## Store policy checklist

| Policy | Status in app |
|--------|---------------|
| No in-app zip updater on store builds | `IsStoreManaged` disables R2 updater |
| External payment links disclosed | Upgrade links point to adkcyber.com (same as Windows) |
| AI content reporting | Report button on AI responses (if not yet on Apple UI, add before submit) |
| Privacy policy linked | In auth overlay and account panel |
| Account required | Login gate before chat |
| Encryption export | `ITSAppUsesNonExemptEncryption = false` |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `0 valid identities found` | Add Apple ID in Xcode → Settings → Accounts; download certs |
| Provisioning profile doesn't match | Regenerate profile after enabling capabilities |
| Mac sandbox rejection | `Platforms/MacCatalyst/Entitlements.plist` includes app-sandbox + network.client |
| iOS upload fails | Confirm `ArchiveOnBuild` + `BuildIpa` and ios-arm64 RID |
| Update banner on iOS | Store channel returns `store`; banner hidden in UI |

---

## Quick reference

```bash
# Local unsigned Release (smoke test)
dotnet publish PanCopilot.Apple/PanCopilot.Apple.csproj -f net8.0-maccatalyst -c Release -r maccatalyst-arm64
dotnet publish PanCopilot.Apple/PanCopilot.Apple.csproj -f net8.0-ios -c Release -r iossimulator-arm64

# Signed store build
./scripts/build-appstore-apple.sh 3.20
```
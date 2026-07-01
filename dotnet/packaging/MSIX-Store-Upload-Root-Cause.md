# MSIX Store Upload — Root-Cause Analysis ("null" error in Partner Center)

**Date:** 2026-06-25
**App:** ADK Cyber AI (internal "PAN Copilot"), .NET 8 + WPF + WebView2
**Symptom:** Uploading the Store MSIX to Microsoft Partner Center fails with a generic
`null` error during package validation. Persists across multiple version bumps
(v3.18.1 → v3.19 → v3.19.1).

---

## TL;DR — Root cause

**The MSIX contains no `resources.pri`.**

Every package is built by the hand-rolled `Build-Msix.ps1`, which runs
`makeappx pack` directly over the `dotnet publish` output. That path **never runs
`makepri`**, so the package ships with no MRT resource index — even though the
manifest declares `<Resources>` and tile/logo visual assets. A Store-bound MSIX
that declares resources/assets but has no `resources.pri` is structurally
invalid; Partner Center's ingestion can't categorize the failure and surfaces it
as the generic **"null"** error.

The defect lives in the **build script**, not the package version — which is why
re-versioning never cleared it.

---

## Status — fix implemented (2026-06-25)

`Build-Msix.ps1` has been patched (Option B below):

- **Generates `resources.pri`** via `makepri createconfig` + `makepri new` over the
  staging folder before `makeappx pack`, with a **post-pack guard** that opens the
  produced `.msix` and throws if `resources.pri` is absent.
- **The upload artifact is now unsigned.** The `.msixupload` is built from the
  unsigned package *before* signing; only the standalone `.msix` (for local
  sideload testing) is self-signed. Partner Center re-signs Store submissions, and
  a pre-applied self-signed signature is itself a known cause of the same "null"
  error — so this was a likely *second* trigger, now removed.
- **Fixed a script-crashing encoding bug:** an em-dash (U+2014) in a string made
  the BOM-less file mis-parse under Windows PowerShell 5.1 (read as Windows-1252);
  replaced with ASCII.
- Minor hardening: x64 SDK tool selection (matches `Sign-StoreMsix.ps1`) and
  fail-loud `priconfig.xml` removal.

Verified by AST parse (no syntax errors) and byte scan (zero non-ASCII). The MSIX
itself could **not** be runtime-built here (no Windows SDK on this machine); it was
instead checked by a 3-lens adversarial code review (makepri correctness ·
PowerShell 5.1 robustness · Store ingestion validity), which concurred the fix is
correct. Generating `resources.pri` is necessary but may not be sufficient alone —
**see the Partner Center pre-flight checklist below.**

## How this was investigated

Systematic debugging (root cause before fix). All evidence below was read
directly from the artifacts and the build pipeline — nothing inferred.

Artifacts examined (in `dotnet/msix-artifact/`):

- `ADK_Cyber_AI_v3.18.1_Store_msix/ADK_Cyber_AI_v3.18.1_Store.msix` (the file reported failing)
- `ADK_Cyber_AI_v3.19.1_Store.msix` (latest attempt)
- `ADK_Cyber_AI_v3.19.1_Store.msixupload`

Pipeline examined (in `dotnet/packaging/`):

- `Build-Msix.ps1`, `Package.appxmanifest`, `Sign-StoreMsix.ps1`,
  `Sync-ManifestIdentity.ps1`, `PartnerCenter.Identity.props`,
  `ADKCyberAI.Package.wapproj`

---

## Evidence

### 1. No `resources.pri` in any package (the persistent defect)

Searched the full ZIP file list of every package. `resources.pri` is **absent**
in v3.18.1, v3.19, and v3.19.1. The manifest nonetheless declares resources and
tile assets:

```xml
<Resources><Resource Language="en-US" /></Resources>
...
<uap:VisualElements ...
    Square150x150Logo="Images\Square150x150Logo.png"
    Square44x44Logo="Images\Square44x44Logo.png">
  <uap:DefaultTile Wide310x150Logo="Images\Wide310x150Logo.png" />
</uap:VisualElements>
```

The standard MSIX toolchain always emits `resources.pri`. Its absence here is the
hallmark of a `makeappx pack`-over-publish-folder build with no `makepri` step.

### 2. The build script has no resource-index step

`Build-Msix.ps1` does, in order: robocopy publish dir → staging, strip `*.pdb`,
rename exe to `ADKCyberAI.exe`, copy `Package.appxmanifest` + `Images`, then
`makeappx pack`, sign, and naively zip the `.msix` into a `.msixupload`. **There
is no `makepri` invocation anywhere.** So the script cannot produce a valid
resource index, by construction.

### 3. Differential: what changed vs. what never changed

| Property | v3.18.1 (reported failing) | v3.19.1 (latest) |
|---|---|---|
| Main exe | `PAN Copilot.exe` (space in entry point) | `ADKCyberAI.exe` ✓ fixed |
| `.pdb` / debug symbols (`createdump.exe`, `mscordaccore*`, `mscordbi`, DiaSymReader) | bundled | stripped ✓ fixed |
| Tile `BackgroundColor` | `transparent` | `#1B2B3A` ✓ fixed |
| Signature (`AppxSignature.p7x`) | unsigned | self-signed ✓ |
| **`resources.pri`** | **MISSING** | **STILL MISSING** ✗ |

The exe name, debug symbols, tile color, and signing were all fixed between
3.18.1 and 3.19.1 — but the missing resource index was never addressed, so the
upload kept failing with the same `null`. The one defect common to **all** failing
versions is the missing `resources.pri`.

### 4. The correct build path exists but was never used

`ADKCyberAI.Package.wapproj` is a proper Windows Application Packaging Project.
A real MSBuild build of it generates `resources.pri`, scale-qualified assets, and
a proper `.msixupload` automatically. There is **no `AppPackages\` output
directory**, confirming the `.wapproj` has never been built — every shipped
artifact came from the `makeappx` shortcut in `Build-Msix.ps1` instead.

---

## Why the "null" error is so unhelpful

Partner Center's package-ingestion validator returns an uncategorized error when
the package is malformed in a way it can't map to a known rule. A package that
declares resources/visual assets with no resource index falls into that bucket,
so the UI renders the error detail as literally `null`. The fix is to make the
package valid, then validate it locally before re-uploading (see below).

---

## Fix

### Option A — Build via the existing `.wapproj` (recommended)

It generates `resources.pri`, scaled assets, and a Store-ready `.msixupload`:

```powershell
msbuild .\packaging\ADKCyberAI.Package.wapproj `
  /p:Configuration=Release /p:Platform=x64 `
  /p:UapAppxPackageBuildMode=StoreUpload
```

Upload the resulting `.msixupload` from `packaging\AppPackages\`.

### Option B — Keep `Build-Msix.ps1`, add a `makepri` step

**✅ This is the path taken.** A `makepri new` step over the staging folder runs
**before** `makeappx pack`:

```powershell
# Generate a default PRI config (once), then build the index over staging:
makepri createconfig /cf "$staging\priconfig.xml" /dq en-US /o
makepri new /pr "$staging" /cf "$staging\priconfig.xml" `
  /mn "$staging\AppxManifest.xml" /of "$staging\resources.pri" /o
Remove-Item "$staging\priconfig.xml" -Force   # don't pack the config
# ...then makeappx pack as before
```

### Verify before re-uploading (either option)

Run the **Windows App Certification Kit (WACK)** against the package locally. It
confirms the package validates before you round-trip through Partner Center's
opaque `null`.

---

## Partner Center pre-flight checklist

`resources.pri` was the structural defect, but the generic "null" error has other
known causes the local analysis cannot rule out. Before re-uploading, verify in
Partner Center:

1. **Upload the UNSIGNED `.msixupload`** (the patched script now produces this).
   Do not upload a self-signed package — the Store re-signs.
2. **Identity matches the reservation byte-for-byte.** Partner Center → Product →
   Product identity must equal the manifest:
   `Name=ADKCyber.ADKCyberAI`, `Publisher=CN=2E570EB4-F656-4F16-AD78-779C9ECF780D`.
3. **Version must exceed every previously-submitted version.** Partner Center can
   permanently burn used version numbers; the earlier 3.18.1 / 3.19 / 3.19.1
   attempts may have consumed those slots. Bump to a clearly-higher version
   (e.g. `3.20.0.0`) to be safe.
4. **Run WACK** (Windows App Certification Kit) on the rebuilt package locally — it
   validates against the same rules and returns a real error instead of "null".

## Known limitations (not blockers)

- **Unqualified tile assets.** The manifest references logos by direct path with no
  `.scale-*` / `.targetsize-*` variants, so WACK will emit *warnings* and Start/
  taskbar icons may look soft on high-DPI displays. This does **not** block
  ingestion. To resolve, drop scale-qualified PNGs into `Images\` (the `.wapproj`
  generates these automatically) before `makepri` runs.
- **Self-signed cert password** in `Sign-StoreMsix.ps1` is hard-coded
  (`AdkStoreMsixSign!`). It guards only a throwaway, per-run self-signed cert used
  for the sideload-test `.msix`, so impact is low — but it is technically a
  secret-in-code and could be randomized per run.

## Caveats / environment notes

- **This machine has no Windows SDK.** `makeappx`, `makepri`, and `signtool` are
  not present under `Windows Kits\10\bin`, `Program Files`, or the NuGet cache.
  Build on a machine with the SDK, or via the `.wapproj` (which pulls
  `Microsoft.Windows.SDK.BuildTools` from NuGet — route that restore through
  `sfw` per the install policy).
- **Upload the `.msixupload`, not the bare `.msix`.** Both formats are accepted,
  but `.msixupload` is the supported/recommended path and avoids a separate class
  of single-package upload quirks.
- The current `.msixupload` is just the single `.msix` re-zipped by
  `Build-Msix.ps1`. The `.wapproj` produces a correctly structured upload bundle.

---

## Confidence

High that the missing `resources.pri` is a blocking structural defect: it is the
single deviation common to every failing version, the build script provably could
not produce it, and the standard toolchain always emits it. A 3-lens adversarial
review concurred the fix is correct and the diagnosis sound, while flagging that
the self-signed upload artifact was a likely *second* cause (now fixed) and that
identity/version must be confirmed in Partner Center.

The exact Partner Center error could not be reproduced locally (no SDK, no Partner
Center access from here), so definitive confirmation is: rebuild on a machine with
the Windows SDK → WACK pass → upload the unsigned `.msixupload` with a fresh
version number.

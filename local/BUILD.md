# PAN Copilot — Desktop Build Guide

Produces a standalone Windows executable: **`dist/PAN Copilot/PAN Copilot.exe`**

No Python required on end-user machines. Everything is bundled.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10/11 (64-bit) | Build must happen on Windows to produce a Windows .exe |
| Python 3.11+ | Download from python.org — check "Add to PATH" during install |
| Git (optional) | Only needed if cloning from source |

---

## Step 1 — Set up your environment

Open **Command Prompt** or **PowerShell** in the `local/` directory:

```cmd
cd "C:\Users\jmill\OneDrive\Documents\Claude\Projects\PAN Copilot\local"
```

Create and activate a virtual environment (recommended to keep deps clean):

```cmd
python -m venv .venv
.venv\Scripts\activate
```

---

## Step 2 — Install dependencies

```cmd
pip install -r requirements.txt
pip install pyinstaller
```

This installs FastAPI, uvicorn, the Anthropic SDK, and PyInstaller itself.

---

## Step 3 — Confirm the files are in place

The `local/` directory must contain all of these before building:

```
local/
├── app.py                          ← FastAPI backend
├── pan_copilot.py                  ← Entry point (port finder + browser launcher)
├── pan_copilot_desktop.html        ← Frontend UI
├── pan_copilot.spec                ← PyInstaller config
├── requirements.txt
└── ../PAN_Copilot_Master_System_Prompt.md   ← Referenced from spec
```

If `pan_copilot_desktop.html` is not in `local/`, copy it there now.

---

## Step 4 — Build the executable

```cmd
pyinstaller pan_copilot.spec
```

PyInstaller will:
1. Analyse all imports
2. Bundle Python + your app + the HTML + the system prompt
3. Write output to `dist/PAN Copilot/`

First build takes 2–5 minutes. Subsequent builds are faster.

**Expected output:**

```
local/
└── dist/
    └── PAN Copilot/
        ├── PAN Copilot.exe     ← The launcher
        ├── _internal/          ← Bundled Python runtime + deps
        └── ...
```

---

## Step 5 — Test before distributing

1. Double-click `dist/PAN Copilot/PAN Copilot.exe`
2. Your default browser should open to `http://127.0.0.1:<port>`
3. On first run you'll see the API key setup overlay — enter a valid Anthropic key
4. Send a test message and confirm streaming works

**If the browser doesn't open**, check that Windows Defender or your AV isn't blocking the process. You may need to add an exception for the `dist/PAN Copilot/` folder.

---

## Step 6 — Package for distribution

Zip the entire `dist/PAN Copilot/` folder:

```cmd
cd dist
powershell Compress-Archive -Path "PAN Copilot" -DestinationPath "PAN_Copilot_Windows.zip"
```

This is what you distribute to users. They unzip and double-click `PAN Copilot.exe` — no installer needed.

---

## Troubleshooting

### "ModuleNotFoundError" on launch
Add the missing module name to `hiddenimports` in `pan_copilot.spec` and rebuild.

### Blank browser window / "Frontend not found"
Make sure `pan_copilot_desktop.html` was in the `local/` directory when you ran `pyinstaller`. The spec bundles it at build time.

### App appears to hang on startup
Temporarily set `console=True` in `pan_copilot.spec` and rebuild. A terminal window will appear showing any Python errors on launch. Revert to `False` after debugging.

### Windows Defender SmartScreen warning on first run
This is expected for unsigned executables. Users click **"More info" → "Run anyway"**. To eliminate the warning permanently, purchase and apply a code-signing certificate to the .exe.

### AV false positive
Common with PyInstaller bundles. Submit the .exe to your AV vendor for whitelisting, or sign the binary.

---

## Optional: Add a custom icon

1. Create or download a 256×256 `.ico` file (e.g., `pan_copilot.ico`) and place it in `local/`
2. In `pan_copilot.spec`, uncomment the icon line:
   ```python
   icon="pan_copilot.ico",
   ```
3. Rebuild

---

## Clean rebuild

If something seems wrong, start fresh:

```cmd
rmdir /s /q build dist
pyinstaller pan_copilot.spec
```

---

## What the user needs to run PAN Copilot

- The `PAN Copilot/` folder (unzipped)
- An **Anthropic API key** from [console.anthropic.com](https://console.anthropic.com)
- Windows 10/11 (64-bit)
- A default browser (Chrome, Edge, Firefox — anything works)

That's it. No Python, no npm, no accounts on our side.

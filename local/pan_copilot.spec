# -*- mode: python ; coding: utf-8 -*-
#
# PAN Copilot â€” PyInstaller build spec
#
# Build command (run from the local/ directory):
#   pyinstaller pan_copilot.spec
#
# Output: dist/PAN Copilot/PAN Copilot.exe   (Windows, one-folder)
#         dist/PAN Copilot.exe                (Windows, onefile â€” slower first launch)
#
# NOTE: Build on Windows to produce a Windows .exe.
#       Build on macOS to produce a macOS .app bundle.
#       PyInstaller does NOT cross-compile.

import os
from pathlib import Path

block_cipher = None

# Data files to bundle alongside the executable
datas = [
    # (source_path, dest_folder_inside_bundle)
    ("pan_copilot_desktop.html",                            "."),
    ("pan_copilot.ico",                                     "."),
    ("kb",                                                  "kb"),  # KB articles directory
]

# Prompt files: CI runs the "Encrypt prompts" step which produces .enc files
# (and deletes the .md plaintext). Local dev builds skip the encrypt step and
# bundle the plaintext .md instead. We add whichever exists at build time, so
# both CI and `python -m pyinstaller pan_copilot.spec` from a dev box work.
_repo_root = Path("..").resolve()
for _name in [
    "PAN_Copilot_Master_System_Prompt.md.enc",
    "PAN_Copilot_Master_System_Prompt_Local.md.enc",
    "PAN_Copilot_Master_System_Prompt.md",
    "PAN_Copilot_Master_System_Prompt_Local.md",
]:
    _src = _repo_root / _name
    if _src.exists():
        datas.append((str(_src), "."))
        print(f"[spec] bundling {_name}")

# Hidden imports that uvicorn/anyio need but PyInstaller misses
hidden_imports = [
    "_prompt_key",  # AES key module written by CI; loaded via importlib at runtime
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    "anyio",
    "anyio._backends._asyncio",
    "anyio._backends._trio",
    "starlette.routing",
    "starlette.middleware",
    "fastapi",
    "httpcore",
    "httpx",
    "h11",
]

a = Analysis(
    ["pan_copilot.py"],
    pathex=[str(Path(".").resolve())],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=["rthook_fix_streams.py"],
    excludes=[
        # These packages are huge and not needed
        "matplotlib", "numpy", "pandas",
        "scipy", "PIL", "cv2", "torch", "tensorflow",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# â”€â”€ One-folder build (faster startup, recommended for distribution) â”€â”€
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PAN Copilot",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,      # Set True temporarily if you need to see error output
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="pan_copilot.ico",
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="PAN Copilot",
)

# â”€â”€ Uncomment below and comment out COLLECT above for a single .exe file â”€â”€
# Single .exe is convenient but has a slower first launch (~5s) while it
# extracts itself to a temp dir on each run.
#
# exe_onefile = EXE(
#     pyz,
#     a.scripts,
#     a.binaries,
#     a.zipfiles,
#     a.datas,
#     [],
#     name="PAN Copilot",
#     debug=False,
#     bootloader_ignore_signals=False,
#     strip=False,
#     upx=True,
#     upx_exclude=[],
#     runtime_tmpdir=None,
#     console=False,
#     disable_windowed_traceback=False,
#     argv_emulation=False,
#     target_arch=None,
#     codesign_identity=None,
#     entitlements_file=None,
# )



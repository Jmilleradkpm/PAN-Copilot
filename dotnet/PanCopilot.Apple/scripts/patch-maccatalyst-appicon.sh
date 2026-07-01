#!/usr/bin/env bash
set -euo pipefail

APPICONSET="$1"
MAC_SRC="$(cd "$(dirname "$0")/.." && pwd)/Resources/AppIcon/mac"

if [[ ! -d "$APPICONSET" ]]; then
  echo "App icon set not found: $APPICONSET" >&2
  exit 1
fi

cp "$MAC_SRC"/*.png "$APPICONSET/"

python3 - "$APPICONSET/Contents.json" <<'PY'
import json
import sys

contents_path = sys.argv[1]
with open(contents_path, encoding="utf-8") as f:
    data = json.load(f)

mac_images = [
    {"idiom": "mac", "size": "16x16", "scale": "1x", "filename": "appicon16x16.png"},
    {"idiom": "mac", "size": "16x16", "scale": "2x", "filename": "appicon16x16@2x.png"},
    {"idiom": "mac", "size": "32x32", "scale": "1x", "filename": "appicon32x32.png"},
    {"idiom": "mac", "size": "32x32", "scale": "2x", "filename": "appicon32x32@2x.png"},
    {"idiom": "mac", "size": "128x128", "scale": "1x", "filename": "appicon128x128.png"},
    {"idiom": "mac", "size": "128x128", "scale": "2x", "filename": "appicon128x128@2x.png"},
    {"idiom": "mac", "size": "256x256", "scale": "1x", "filename": "appicon256x256.png"},
    {"idiom": "mac", "size": "256x256", "scale": "2x", "filename": "appicon256x256@2x.png"},
    {"idiom": "mac", "size": "512x512", "scale": "1x", "filename": "appicon512x512.png"},
    {"idiom": "mac", "size": "512x512", "scale": "2x", "filename": "appicon512x512@2x.png"},
]

existing = {img.get("filename") for img in data.get("images", [])}
for img in mac_images:
    if img["filename"] not in existing:
        data.setdefault("images", []).append(img)

with open(contents_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
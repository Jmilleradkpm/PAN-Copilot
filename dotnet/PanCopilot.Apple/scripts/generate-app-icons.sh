#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ICON_SRC="$(cd "$ROOT/../.." && pwd)/pan_copilot.ico"
ICON_DIR="$ROOT/Resources/AppIcon"

mkdir -p "$ICON_DIR"

sips -s format png "$ICON_SRC" --out /tmp/pan_icon_256.png >/dev/null
sips -z 1024 1024 /tmp/pan_icon_256.png --out "$ICON_DIR/appicon.png" >/dev/null

# App Store requires the 1024 marketing icon to have no alpha channel.
python3 - <<'PY'
from PIL import Image
path = "$ICON_DIR/appicon.png"
img = Image.open(path).convert("RGBA")
bg = Image.new("RGBA", img.size, (10, 22, 40, 255))  # #0a1628
Image.alpha_composite(bg, img).convert("RGB").save(path, "PNG")
PY

ICONSET="/tmp/AppIcon.iconset"
rm -rf "$ICONSET" && mkdir -p "$ICONSET"
SRC="$ICON_DIR/appicon.png"
sips -z 16 16   "$SRC" --out "$ICONSET/icon_16x16.png" >/dev/null
sips -z 32 32   "$SRC" --out "$ICONSET/icon_16x16@2x.png" >/dev/null
sips -z 32 32   "$SRC" --out "$ICONSET/icon_32x32.png" >/dev/null
sips -z 64 64   "$SRC" --out "$ICONSET/icon_32x32@2x.png" >/dev/null
sips -z 128 128 "$SRC" --out "$ICONSET/icon_128x128.png" >/dev/null
sips -z 256 256 "$SRC" --out "$ICONSET/icon_128x128@2x.png" >/dev/null
sips -z 256 256 "$SRC" --out "$ICONSET/icon_256x256.png" >/dev/null
sips -z 512 512 "$SRC" --out "$ICONSET/icon_256x256@2x.png" >/dev/null
sips -z 512 512 "$SRC" --out "$ICONSET/icon_512x512.png" >/dev/null
cp "$SRC" "$ICONSET/icon_512x512@2x.png"
iconutil -c icns "$ICONSET" -o "$ICON_DIR/appicon.icns"

MAC_DIR="$ICON_DIR/mac"
rm -rf "$MAC_DIR" && mkdir -p "$MAC_DIR"
sips -z 16 16   "$SRC" --out "$MAC_DIR/appicon16x16.png" >/dev/null
sips -z 32 32   "$SRC" --out "$MAC_DIR/appicon16x16@2x.png" >/dev/null
sips -z 32 32   "$SRC" --out "$MAC_DIR/appicon32x32.png" >/dev/null
sips -z 64 64   "$SRC" --out "$MAC_DIR/appicon32x32@2x.png" >/dev/null
sips -z 128 128 "$SRC" --out "$MAC_DIR/appicon128x128.png" >/dev/null
sips -z 256 256 "$SRC" --out "$MAC_DIR/appicon128x128@2x.png" >/dev/null
sips -z 256 256 "$SRC" --out "$MAC_DIR/appicon256x256.png" >/dev/null
sips -z 512 512 "$SRC" --out "$MAC_DIR/appicon256x256@2x.png" >/dev/null
sips -z 512 512 "$SRC" --out "$MAC_DIR/appicon512x512.png" >/dev/null
cp "$SRC" "$MAC_DIR/appicon512x512@2x.png"

echo "Generated app icons in $ICON_DIR"
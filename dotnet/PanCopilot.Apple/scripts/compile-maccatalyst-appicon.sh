#!/usr/bin/env bash
# Compile MauiIcon Assets.xcassets into Assets.car for Mac App Store validation.
set -euo pipefail

ASSETS_CATALOG="$1"
OUTPUT_DIR="$2"
PARTIAL_PLIST="$3"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -d "$ASSETS_CATALOG/appicon.appiconset" ]]; then
  echo "Missing appicon.appiconset in $ASSETS_CATALOG" >&2
  exit 1
fi

bash "$SCRIPT_DIR/patch-maccatalyst-appicon.sh" "$ASSETS_CATALOG/appicon.appiconset"

mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR/Assets.car" "$OUTPUT_DIR"/*.png "$OUTPUT_DIR"/*.icns "$PARTIAL_PLIST"

python3 - "$ASSETS_CATALOG" <<'PY'
import sys
from pathlib import Path
from PIL import Image

catalog = Path(sys.argv[1])
for png in catalog.rglob("*.png"):
    img = Image.open(png).convert("RGBA")
    bg = Image.new("RGBA", img.size, (10, 22, 40, 255))
    Image.alpha_composite(bg, img).convert("RGB").save(png, "PNG")
PY

xcrun actool --output-partial-info-plist "$PARTIAL_PLIST" \
  --app-icon appicon \
  --platform macosx \
  --minimum-deployment-target 15.0 \
  --compile "$OUTPUT_DIR" \
  "$ASSETS_CATALOG"

test -f "$OUTPUT_DIR/Assets.car"
echo "Compiled Mac Catalyst app icons -> $OUTPUT_DIR/Assets.car"
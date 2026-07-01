#!/usr/bin/env bash
# Compile MauiIcon Assets.xcassets into Assets.car for iOS App Store validation.
set -euo pipefail

ASSETS_CATALOG="$1"
OUTPUT_DIR="$2"
PARTIAL_PLIST="$3"

if [[ ! -d "$ASSETS_CATALOG/appicon.appiconset" ]]; then
  echo "Missing appicon.appiconset in $ASSETS_CATALOG" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR/Assets.car" "$OUTPUT_DIR"/*.png "$PARTIAL_PLIST"

xcrun actool --output-partial-info-plist "$PARTIAL_PLIST" \
  --app-icon appicon \
  --compress-pngs \
  --platform iphoneos \
  --minimum-deployment-target 15.0 \
  --compile "$OUTPUT_DIR" \
  "$ASSETS_CATALOG"

test -f "$OUTPUT_DIR/Assets.car"
echo "Compiled iOS app icons -> $OUTPUT_DIR/Assets.car"
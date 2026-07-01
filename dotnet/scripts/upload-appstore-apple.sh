#!/usr/bin/env bash
# Upload Mac .pkg and iOS .ipa to App Store Connect.
# Auth (pick one):
#   A) App Store Connect API key:
#        export APP_STORE_CONNECT_API_KEY="XXXXXXXXXX"
#        export APP_STORE_CONNECT_ISSUER_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
#        export APP_STORE_CONNECT_API_KEY_PATH="$HOME/.appstoreconnect/AuthKey_XXXXXXXXXX.p8"
#   B) Apple ID (not recommended for CI):
#        export APPLE_ID="you@example.com"
#        export APPLE_APP_SPECIFIC_PASSWORD="xxxx-xxxx-xxxx-xxxx"
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAC_PKG=$(ls -t "$ROOT/publish/appstore/maccatalyst"/*.pkg 2>/dev/null | head -1)
IOS_IPA=$(ls -t "$ROOT/publish/appstore/ios"/*.ipa 2>/dev/null | head -1)

if [[ -z "${MAC_PKG:-}" || -z "${IOS_IPA:-}" ]]; then
  echo "Missing artifacts. Run ./scripts/build-appstore-apple.sh 3.20 first."
  exit 1
fi

echo "Mac:  $MAC_PKG"
echo "iOS:  $IOS_IPA"
echo ""

upload_one() {
  local file="$1"
  local type="$2"
  echo "==> Uploading $type: $(basename "$file")"
  if [[ -n "${APP_STORE_CONNECT_API_KEY_PATH:-}" && -n "${APP_STORE_CONNECT_API_KEY:-}" && -n "${APP_STORE_CONNECT_ISSUER_ID:-}" ]]; then
    xcrun altool --upload-package "$file" \
      --type "$type" \
      --api-key "$APP_STORE_CONNECT_API_KEY" \
      --api-issuer "$APP_STORE_CONNECT_ISSUER_ID" \
      --api-key-file "$APP_STORE_CONNECT_API_KEY_PATH"
  elif [[ -n "${APPLE_ID:-}" && -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]]; then
    xcrun altool --upload-package "$file" \
      --type "$type" \
      --username "$APPLE_ID" \
      --password "$APPLE_APP_SPECIFIC_PASSWORD"
  else
    echo "No upload credentials set."
    echo "Open Transporter and drag these files in, or set API key / Apple ID env vars (see script header)."
    open -a Transporter "$file" 2>/dev/null || open -a "Transporter" "$file" 2>/dev/null || true
    return 1
  fi
}

FAIL=0
upload_one "$IOS_IPA" ios || FAIL=1
upload_one "$MAC_PKG" macos || FAIL=1

if [[ "$FAIL" -eq 0 ]]; then
  echo ""
  echo "Upload complete. Check App Store Connect → TestFlight (processing ~10–30 min)."
  echo "Then attach builds to your 3.20.0 version and submit for review."
else
  echo ""
  echo "Opened Transporter for manual upload (if installed)."
  exit 1
fi
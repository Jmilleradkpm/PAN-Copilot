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
TARGET="${1:-all}"

pick_mac_pkg() {
  local signed unsigned
  signed=$(ls -t "$ROOT/publish/appstore/maccatalyst"/*-signed.pkg 2>/dev/null | head -1)
  if [[ -n "${signed:-}" ]]; then
    echo "$signed"
    return
  fi
  unsigned=$(ls -t "$ROOT/publish/appstore/maccatalyst"/*.pkg 2>/dev/null | grep -v -- '-signed\.pkg$' | head -1)
  echo "${unsigned:-}"
}

MAC_PKG="$(pick_mac_pkg)"
IOS_IPA=$(ls -t "$ROOT/publish/appstore/ios"/*.ipa 2>/dev/null | head -1)

if [[ "$TARGET" == "mac" || "$TARGET" == "macos" ]]; then
  [[ -n "${MAC_PKG:-}" ]] || { echo "Missing Mac .pkg. Run ./scripts/build-appstore-apple.sh 3.20 first."; exit 1; }
elif [[ "$TARGET" == "ios" ]]; then
  [[ -n "${IOS_IPA:-}" ]] || { echo "Missing iOS .ipa. Run ./scripts/build-appstore-apple.sh 3.20 first."; exit 1; }
else
  if [[ -z "${MAC_PKG:-}" || -z "${IOS_IPA:-}" ]]; then
    echo "Missing artifacts. Run ./scripts/build-appstore-apple.sh 3.20 first."
    exit 1
  fi
fi

if [[ -n "${MAC_PKG:-}" ]]; then
  echo "Mac:  $MAC_PKG"
  if ! pkgutil --check-signature "$MAC_PKG" 2>/dev/null | grep -q "Status: signed"; then
    echo "ERROR: Mac .pkg is not installer-signed."
    echo "Create Mac Installer Distribution in Xcode, then run:"
    echo "  ./scripts/sign-mac-appstore-pkg.sh \"$MAC_PKG\""
    exit 1
  fi
fi
[[ -n "${IOS_IPA:-}" ]] && echo "iOS:  $IOS_IPA"
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
if [[ "$TARGET" == "ios" ]]; then
  upload_one "$IOS_IPA" ios || FAIL=1
elif [[ "$TARGET" == "mac" || "$TARGET" == "macos" ]]; then
  upload_one "$MAC_PKG" macos || FAIL=1
else
  upload_one "$IOS_IPA" ios || FAIL=1
  upload_one "$MAC_PKG" macos || FAIL=1
fi

if [[ "$FAIL" -eq 0 ]]; then
  echo ""
  echo "Upload complete. Check App Store Connect → TestFlight (processing ~10–30 min)."
  echo "Then attach builds to your 3.20.0 version and submit for review."
else
  echo ""
  echo "Opened Transporter for manual upload (if installed)."
  exit 1
fi
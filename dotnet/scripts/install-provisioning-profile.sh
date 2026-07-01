#!/usr/bin/env bash
# Install App Store / Distribution provisioning profiles for dotnet/Xcode builds.
# Usage: ./scripts/install-provisioning-profile.sh ~/Downloads/ADK_Cyber_AI_Mac_App_Store.provisionprofile
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <path-to.provisionprofile> [another.provisionprofile ...]"
  exit 1
fi

DEST="$HOME/Library/MobileDevice/Provisioning Profiles"
mkdir -p "$DEST"

for profile in "$@"; do
  if [[ ! -f "$profile" ]]; then
    echo "Not found: $profile"
    exit 1
  fi
  uuid=$(security cms -D -i "$profile" 2>/dev/null | plutil -extract UUID raw - 2>/dev/null || true)
  name=$(security cms -D -i "$profile" 2>/dev/null | plutil -extract Name raw - 2>/dev/null || true)
  if [[ -z "$uuid" ]]; then
    echo "Could not read profile UUID: $profile"
    exit 1
  fi
  cp "$profile" "$DEST/${uuid}.provisionprofile"
  echo "Installed: ${name:-$profile}"
  echo "  -> $DEST/${uuid}.provisionprofile"
done

echo ""
echo "Run ./scripts/verify-appstore-ready.sh to confirm."
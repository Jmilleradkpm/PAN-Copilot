#!/usr/bin/env bash
# Quick checklist before running build-appstore-apple.sh
set -euo pipefail

BUNDLE_ID="com.adkcyber.pancopilot"
TEAM_ID="${APPLE_TEAM_ID:-VPV4CVFJYL}"
OK=0
FAIL=0

pass() { echo "  ✓ $1"; OK=$((OK + 1)); }
fail() { echo "  ✗ $1"; FAIL=$((FAIL + 1)); }

echo "ADK Cyber AI — App Store readiness"
echo "Bundle ID: $BUNDLE_ID"
echo "Team ID:   $TEAM_ID"
echo ""

echo "Code signing identities:"
if security find-identity -v -p codesigning 2>/dev/null | grep -q "Apple Distribution"; then
  pass "Apple Distribution certificate installed"
  security find-identity -v -p codesigning 2>/dev/null | grep "Apple Distribution" | sed 's/^/    /'
else
  fail "Apple Distribution certificate missing (Xcode → Settings → Accounts → Manage Certificates)"
fi

if security find-identity -v -p codesigning 2>/dev/null | grep -q "Apple Development"; then
  pass "Apple Development certificate installed"
else
  fail "Apple Development certificate missing"
fi

echo ""
echo "Provisioning profiles:"
PROFILE_DIR="$HOME/Library/MobileDevice/Provisioning Profiles"
COUNT=0
if [[ -d "$PROFILE_DIR" ]]; then
  COUNT=$(find "$PROFILE_DIR" -name "*.provisionprofile" 2>/dev/null | wc -l | tr -d ' ')
fi
if [[ "$COUNT" -gt 0 ]]; then
  pass "$COUNT provisioning profile(s) installed"
  find "$PROFILE_DIR" -name "*.provisionprofile" 2>/dev/null | while read -r p; do
    name=$(security cms -D -i "$p" 2>/dev/null | plutil -extract Name raw - 2>/dev/null || echo "unknown")
    appid=$(security cms -D -i "$p" 2>/dev/null | plutil -extract Entitlements.application-identifier raw - 2>/dev/null || echo "")
    echo "    - $name ${appid:+($appid)}"
  done
else
  fail "No provisioning profiles found — create App Store profiles in developer.apple.com"
fi

MAC_PROFILE="${APPLE_CODESIGN_PROVISION_MAC:-ADK Cyber AI Mac App Store}"
IOS_PROFILE="${APPLE_CODESIGN_PROVISION_IOS:-ADK Cyber AI iOS App Store}"
if [[ -d "$PROFILE_DIR" ]] && find "$PROFILE_DIR" -name "*.provisionprofile" -print0 2>/dev/null | xargs -0 -I{} sh -c 'security cms -D -i "$1" 2>/dev/null' _ {} | grep -q "$BUNDLE_ID"; then
  pass "Profile references $BUNDLE_ID"
else
  fail "No profile for $BUNDLE_ID yet"
fi

echo ""
echo "Build inputs:"
if [[ -f PanCopilot.Core/Services/system_prompt.bin ]]; then
  pass "Encrypted system prompt (production)"
elif [[ -f PAN_Copilot_Master_System_Prompt.md ]]; then
  pass "Plaintext system prompt (dev builds only)"
else
  fail "System prompt missing"
fi

if command -v dotnet >/dev/null 2>&1 || [[ -x "$HOME/.dotnet/dotnet" ]]; then
  pass ".NET SDK available"
else
  fail ".NET SDK not found"
fi

echo ""
if [[ "$FAIL" -eq 0 ]]; then
  echo "Ready to run: source scripts/apple-store.env && ./scripts/build-appstore-apple.sh 3.20"
else
  echo "$FAIL check(s) failed — see APP_STORE.md Phase 1 (App ID + provisioning profiles)"
fi
exit "$FAIL"
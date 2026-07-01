#!/usr/bin/env bash
# Rebuild + sign Mac App Store pkg (build 3201) after UIDeviceFamily fix.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

source scripts/apple-store.env
export PATH="${HOME}/.dotnet:${PATH}"

if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet not found. Install .NET 8 SDK or add it to PATH." >&2
  exit 1
fi

echo "=== dotnet publish (build 3201) ==="
dotnet publish PanCopilot.Apple/PanCopilot.Apple.csproj \
  -f net8.0-maccatalyst \
  -c Release \
  -r maccatalyst-arm64 \
  -p:CreatePackage=true \
  -p:EnableCodeSigning=true \
  -p:AppleTeamId="$APPLE_TEAM_ID" \
  -p:CodesignKey="$APPLE_CODESIGN_KEY" \
  -p:CodesignProvision="$APPLE_CODESIGN_PROVISION_MAC" \
  -o publish/appstore/maccatalyst

INFO_PLIST="PanCopilot.Apple/bin/Release/net8.0-maccatalyst/maccatalyst-arm64/ADK Cyber AI.app/Contents/Info.plist"
echo ""
echo "=== UIDeviceFamily check ==="
plutil -p "$INFO_PLIST" | grep -A3 UIDeviceFamily

UNSIGNED="$(ls -t publish/appstore/maccatalyst/ADK*.pkg 2>/dev/null | grep -v -- '-signed\.pkg$' | head -1)"
echo ""
echo "=== Installer cert check ==="
bash scripts/check-installer-cert.sh "$UNSIGNED"
echo ""
echo "=== Sign unsigned pkg: $UNSIGNED ==="
bash scripts/sign-mac-appstore-pkg.sh "$UNSIGNED"

SIGNED="${UNSIGNED%.pkg}-signed.pkg"
echo ""
echo "=== Open Transporter ==="
open -a Transporter "$SIGNED"

echo ""
echo "Done."
echo "  App: PanCopilot.Apple/bin/Release/net8.0-maccatalyst/maccatalyst-arm64/ADK Cyber AI.app"
echo "  Unsigned pkg: $UNSIGNED"
echo "  Signed pkg:   $SIGNED"
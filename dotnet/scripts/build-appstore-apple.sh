#!/usr/bin/env bash
# Build signed Mac App Store (.pkg) and iOS App Store (.ipa) packages.
# Requires: Xcode, .NET 8 + MAUI workload, Apple Developer account,
# distribution certificate, and provisioning profiles installed on this Mac.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-3.20}"
VERSION_TAG="v${VERSION#v}"
BUILD_CONFIG="${BUILD_CONFIG:-Release}"
OUT="$ROOT/publish/appstore"

: "${APPLE_TEAM_ID:?Set APPLE_TEAM_ID (10-char Team ID from developer.apple.com)}"
: "${APPLE_CODESIGN_KEY:?Set APPLE_CODESIGN_KEY (e.g. 'Apple Distribution: Adirondack CyberSecurity (TEAMID)')}"
: "${APPLE_CODESIGN_PROVISION_MAC:?Set APPLE_CODESIGN_PROVISION_MAC (Mac App Store profile name)}"
: "${APPLE_CODESIGN_PROVISION_IOS:?Set APPLE_CODESIGN_PROVISION_IOS (iOS App Store profile name)}"

export PATH="${HOME}/.dotnet:${PATH}"

echo "==> Version ${VERSION_TAG}"
echo "==> Team ${APPLE_TEAM_ID}"

for proj in PanCopilot.Core/PanCopilot.Core.csproj PanCopilot.Apple/PanCopilot.Apple.csproj; do
  sed -i '' "s/<ApplicationDisplayVersion>.*<\/ApplicationDisplayVersion>/<ApplicationDisplayVersion>${VERSION_TAG}<\/ApplicationDisplayVersion>/" "$proj" 2>/dev/null \
    || sed -i "s/<ApplicationDisplayVersion>.*<\/ApplicationDisplayVersion>/<ApplicationDisplayVersion>${VERSION_TAG}<\/ApplicationDisplayVersion>/" "$proj"
done

if [[ ! -f PanCopilot.Core/Services/system_prompt.bin ]]; then
  if [[ -f PAN_Copilot_Master_System_Prompt.md ]]; then
    echo "==> Using plaintext PAN_Copilot_Master_System_Prompt.md (dev only)"
  else
    echo "ERROR: Encrypt system prompt first (see build-release-apple.yml) or place PAN_Copilot_Master_System_Prompt.md for local dev."
    exit 1
  fi
fi

dotnet restore PanCopilot.sln

mkdir -p "$OUT/maccatalyst" "$OUT/ios"

echo "==> Mac Catalyst App Store package"
APPLE_CODESIGN_PROVISION="$APPLE_CODESIGN_PROVISION_MAC" \
dotnet publish PanCopilot.Apple/PanCopilot.Apple.csproj \
  -f net8.0-maccatalyst \
  -c "$BUILD_CONFIG" \
  -r maccatalyst-arm64 \
  -p:CreatePackage=true \
  -p:EnableCodeSigning=true \
  -p:AppleTeamId="$APPLE_TEAM_ID" \
  -p:CodesignKey="$APPLE_CODESIGN_KEY" \
  -p:CodesignProvision="$APPLE_CODESIGN_PROVISION_MAC" \
  -o "$OUT/maccatalyst"

echo "==> iOS App Store IPA"
APPLE_CODESIGN_PROVISION="$APPLE_CODESIGN_PROVISION_IOS" \
dotnet publish PanCopilot.Apple/PanCopilot.Apple.csproj \
  -f net8.0-ios \
  -c "$BUILD_CONFIG" \
  -r ios-arm64 \
  -p:ArchiveOnBuild=true \
  -p:BuildIpa=true \
  -p:EnableCodeSigning=true \
  -p:AppleTeamId="$APPLE_TEAM_ID" \
  -p:CodesignKey="$APPLE_CODESIGN_KEY" \
  -p:CodesignProvision="$APPLE_CODESIGN_PROVISION_IOS" \
  -o "$OUT/ios"

echo ""
echo "Done. Upload artifacts from:"
echo "  Mac:  $OUT/maccatalyst/*.pkg"
echo "  iOS:  $OUT/ios/*.ipa"
echo ""
echo "Next: Transporter app or 'xcrun altool --upload-app' to App Store Connect."
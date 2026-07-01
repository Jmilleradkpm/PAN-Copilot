#!/usr/bin/env bash
# Build signed Mac App Store (.pkg) and iOS App Store (.ipa) packages.
# Requires: Xcode, .NET 8 + MAUI workload, Apple Developer account,
# distribution certificate, and provisioning profiles installed on this Mac.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f "$ROOT/scripts/apple-store.env" ]]; then
  # shellcheck source=/dev/null
  source "$ROOT/scripts/apple-store.env"
fi

VERSION="${1:-3.20}"
VERSION="${VERSION#v}"
VERSION_TAG="$VERSION"
BUILD_NUMBER="${VERSION//./}"
BUILD_CONFIG="${BUILD_CONFIG:-Release}"
OUT="$ROOT/publish/appstore"

: "${APPLE_TEAM_ID:?Set APPLE_TEAM_ID (10-char Team ID from developer.apple.com)}"
: "${APPLE_CODESIGN_KEY:?Set APPLE_CODESIGN_KEY (e.g. 'Apple Distribution: Adirondack CyberSecurity (TEAMID)')}"
: "${APPLE_CODESIGN_PROVISION_MAC:?Set APPLE_CODESIGN_PROVISION_MAC (Mac App Store profile name)}"
: "${APPLE_CODESIGN_PROVISION_IOS:?Set APPLE_CODESIGN_PROVISION_IOS (iOS App Store profile name)}"

export PATH="${HOME}/.dotnet:${PATH}"

echo "==> Version ${VERSION_TAG}"
echo "==> Team ${APPLE_TEAM_ID}"

DISPLAY_VERSION="${VERSION}.0"
[[ "$VERSION" == *.*.* ]] && DISPLAY_VERSION="$VERSION"
sed -i '' "s/<Version>.*<\/Version>/<Version>${DISPLAY_VERSION}<\/Version>/" PanCopilot.Core/PanCopilot.Core.csproj 2>/dev/null \
  || sed -i "s/<Version>.*<\/Version>/<Version>${DISPLAY_VERSION}<\/Version>/" PanCopilot.Core/PanCopilot.Core.csproj
sed -i '' "s/<ApplicationDisplayVersion>.*<\/ApplicationDisplayVersion>/<ApplicationDisplayVersion>${DISPLAY_VERSION}<\/ApplicationDisplayVersion>/" PanCopilot.Apple/PanCopilot.Apple.csproj 2>/dev/null \
  || sed -i "s/<ApplicationDisplayVersion>.*<\/ApplicationDisplayVersion>/<ApplicationDisplayVersion>${DISPLAY_VERSION}<\/ApplicationDisplayVersion>/" PanCopilot.Apple/PanCopilot.Apple.csproj
# CFBundleVersion build number (e.g. 3.20.0 -> 3200)
BUILD_INT=$(echo "$DISPLAY_VERSION" | tr -d '.')
sed -i '' "s/<ApplicationVersion>.*<\/ApplicationVersion>/<ApplicationVersion>${BUILD_INT}<\/ApplicationVersion>/" PanCopilot.Apple/PanCopilot.Apple.csproj 2>/dev/null \
  || sed -i "s/<ApplicationVersion>.*<\/ApplicationVersion>/<ApplicationVersion>${BUILD_INT}<\/ApplicationVersion>/" PanCopilot.Apple/PanCopilot.Apple.csproj

if [[ ! -f PanCopilot.Core/Services/system_prompt.bin ]]; then
  if [[ -f PAN_Copilot_Master_System_Prompt.md ]]; then
    echo "==> Using plaintext PAN_Copilot_Master_System_Prompt.md (dev only)"
  else
    echo "ERROR: Encrypt system prompt first (see build-release-apple.yml) or place PAN_Copilot_Master_System_Prompt.md for local dev."
    exit 1
  fi
fi

# Store builds must be clean: incremental builds can package a .dll from one
# compilation with .aotdata from another, and mismatched AOT images abort the
# Mono runtime at launch on device (SIGABRT in load_aot_module, AOT-only mode).
# This is exactly what shipped in build 3204 — never skip this step.
echo "==> Cleaning bin/obj for a reproducible store build"
rm -rf PanCopilot.Apple/bin PanCopilot.Apple/obj PanCopilot.Core/bin PanCopilot.Core/obj

dotnet restore PanCopilot.Apple/PanCopilot.Apple.csproj

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

MAC_PKG=$(ls -t "$OUT/maccatalyst"/*.pkg 2>/dev/null | grep -v -- '-signed\.pkg$' | head -1)
if [[ -n "${MAC_PKG:-}" ]]; then
  if bash "$ROOT/scripts/sign-mac-appstore-pkg.sh" "$MAC_PKG"; then
    SIGNED_PKG="${MAC_PKG%.pkg}-signed.pkg"
    cp -f "$SIGNED_PKG" "$OUT/maccatalyst/ADK Cyber AI-${DISPLAY_VERSION}.pkg"
    echo "==> Mac App Store package signed: $OUT/maccatalyst/ADK Cyber AI-${DISPLAY_VERSION}.pkg"
  else
    echo "WARN: Mac .pkg is unsigned. Create a Mac Installer Distribution cert, then run:"
    echo "  ./scripts/sign-mac-appstore-pkg.sh \"$MAC_PKG\""
  fi
fi

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
echo "  Mac:  $OUT/maccatalyst/ADK Cyber AI-${DISPLAY_VERSION}.pkg (must be installer-signed)"
echo "  iOS:  $OUT/ios/*.ipa"
echo ""
echo "Next: Transporter app or 'xcrun altool --upload-app' to App Store Connect."
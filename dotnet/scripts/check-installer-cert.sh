#!/usr/bin/env bash
# Quick diagnostic for Mac Installer Distribution signing issues.
set -euo pipefail

echo "=== Valid installer identities (policy: basic) ==="
security find-identity -v -p basic 2>/dev/null | grep -iE 'installer|valid identities' || true
echo ""

echo "=== App signing identities (policy: codesigning) ==="
security find-identity -v -p codesigning 2>/dev/null | grep -iE 'distribution|installer|valid identities' || true
echo ""

echo "=== Installer cert in login keychain ==="
found=0
for label in "3rd Party Mac Developer Installer" "Mac Installer Distribution"; do
  if cert="$(security find-certificate -a -c "$label" -p "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null | openssl x509 -noout -subject -dates 2>/dev/null | head -2)"; then
    echo "[$label]"
    echo "$cert"
    found=1
  fi
done
if [[ "$found" -eq 0 ]]; then
  echo "No installer certificate found in login keychain (check valid identities above)."
fi
echo ""

PKG="${1:-}"
if [[ -z "$PKG" ]]; then
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  PKG="$(ls -t "$ROOT/publish/appstore/maccatalyst"/*.pkg 2>/dev/null | grep -v -- '-signed\.pkg$' | head -1 || true)"
fi

if [[ -n "${PKG:-}" && -f "$PKG" ]]; then
  echo "=== pkg signature: $(basename "$PKG") ==="
  pkgutil --check-signature "$PKG" 2>&1 || true
else
  echo "No .pkg to check. Pass path as first argument."
fi
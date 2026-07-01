#!/usr/bin/env bash
# Sign a Mac App Store .pkg produced by build-appstore-apple.sh.
# Requires a Mac Installer Distribution (or 3rd Party Mac Developer Installer) cert.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -f "$ROOT/scripts/apple-store.env" ]]; then
  # shellcheck source=/dev/null
  source "$ROOT/scripts/apple-store.env"
fi

UNSIGNED="${1:-$(ls -t "$ROOT/publish/appstore/maccatalyst"/*.pkg 2>/dev/null | grep -v -- '-signed\.pkg$' | head -1)}"
: "${UNSIGNED:?No unsigned .pkg found. Pass path or run build-appstore-apple.sh first.}"

SIGNED="${UNSIGNED%.pkg}-signed.pkg"

strip_quotes() {
  local value="$1"
  value="${value#\"}"
  value="${value%\"}"
  value="${value#$'\u201c'}"
  value="${value%$'\u201d'}"
  value="${value#\'}"
  value="${value%\'}"
  printf '%s' "$value"
}

parse_identity_line() {
  local line="$1"
  local hash name

  [[ "$line" =~ ^[[:space:]]*[0-9]+\)[[:space:]]+([A-Fa-f0-9]{40}) ]] || return 1
  hash="${BASH_REMATCH[1]}"

  name="${line#*)}"
  name="${name#"${name%%[![:space:]]*}"}"
  name="${name#"$hash"}"
  name="${name#"${name%%[![:space:]]*}"}"
  name="$(strip_quotes "$name")"

  [[ -n "$hash" && -n "$name" ]] || return 1
  printf '%s\t%s\n' "$hash" "$name"
}

list_installer_identities() {
  while IFS= read -r line; do
    parse_identity_line "$line" || true
  done < <(
    security find-identity -v -p basic 2>/dev/null \
      | grep -iE 'Mac Installer Distribution|3rd Party Mac Developer Installer'
  )
}

pick_installer_identity() {
  local preferred="$1"
  local hash name
  local -a rows=()
  local fallback=""

  while IFS=$'\t' read -r hash name; do
    rows+=("$hash"$'\t'"$name")
    [[ -z "$fallback" ]] && fallback="$hash"$'\t'"$name"
    if [[ -n "$preferred" && "$name" == "$preferred" ]]; then
      echo "$hash"$'\t'"$name"
      return 0
    fi
  done < <(list_installer_identities)

  if [[ ${#rows[@]} -eq 0 ]]; then
    return 1
  fi

  if [[ -n "$preferred" ]]; then
    echo "WARN: APPLE_INSTALLER_CODESIGN_KEY not found; using first installer identity." >&2
    echo "      Wanted: $preferred" >&2
    for row in "${rows[@]}"; do
      echo "      Found:  ${row#*$'\t'}" >&2
    done
  fi

  echo "$fallback"
}

print_installer_help() {
  cat >&2 <<'EOF'
No usable installer signing identity found in Keychain.

Mac App Store .pkg files need an installer cert (separate from Apple Distribution):
  - Mac Installer Distribution
  - 3rd Party Mac Developer Installer

Create one:
  Xcode → Settings → Accounts → Manage Certificates → + → Mac Installer Distribution

Then verify:
  security find-identity -v -p basic | grep -i installer

Common fixes if the name appears but signing fails:
  - Certificate imported without private key → revoke and recreate in Xcode on this Mac
  - Login keychain locked → run: security unlock-keychain ~/Library/Keychains/login.keychain-db
  - Expired/revoked cert → create a new installer cert
EOF
}

INSTALLER_HASH=""
INSTALLER_NAME=""
if identity="$(pick_installer_identity "${APPLE_INSTALLER_CODESIGN_KEY:-}")"; then
  IFS=$'\t' read -r INSTALLER_HASH INSTALLER_NAME <<< "$identity"
else
  echo "DEBUG: security find-identity -v -p basic | grep -i installer:" >&2
  security find-identity -v -p basic 2>/dev/null | grep -i installer >&2 || true
  print_installer_help
  exit 1
fi

echo "Installer identity: $INSTALLER_NAME"
echo "SHA-1:              $INSTALLER_HASH"
echo "Signing:            $UNSIGNED"
echo "Output:             $SIGNED"

security unlock-keychain -u "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1 || true
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1 || true

if ! productsign --sign "$INSTALLER_HASH" "$UNSIGNED" "$SIGNED"; then
  echo "" >&2
  echo "productsign failed; retrying with identity name..." >&2
  if ! productsign --sign "$INSTALLER_NAME" "$UNSIGNED" "$SIGNED"; then
    echo "" >&2
    echo "productsign failed. Valid installer identities:" >&2
    list_installer_identities | while IFS=$'\t' read -r hash name; do
      echo "  $hash  \"$name\"" >&2
    done
    print_installer_help
    exit 1
  fi
fi

pkgutil --check-signature "$SIGNED"
echo ""
echo "Signed package: $SIGNED"
echo "Upload this file in Transporter (not the unsigned .pkg)."
#!/bin/bash
# Back up the Connect IQ developer key (needed to publish store updates) to
# 1Password as a document item, then download it again and compare.
#
# Usage: scripts/save-key-1password.sh [key.der]
#   OMAMORI_OP_VAULT  vault name (default: your default vault)
#   OMAMORI_OP_TITLE  item title (default: "Omamori Connect IQ developer key")
set -euo pipefail

key=${1:-}
if [ -z "$key" ]; then
  for candidate in "$HOME/Documents/omamori-key/developer_key.der" \
                   "$HOME/Work/.omamori-key-transfer/developer_key.der"; do
    if [ -f "$candidate" ]; then key=$candidate; break; fi
  done
fi
if [ -z "$key" ] || [ ! -f "$key" ]; then
  echo "developer key not found; pass its path as the first argument" >&2
  exit 1
fi
if ! command -v op >/dev/null; then
  echo "1Password CLI (op) not found. Install 1password-cli and enable" >&2
  echo "Settings > Developer > Integrate with 1Password CLI in the app." >&2
  exit 1
fi

title=${OMAMORI_OP_TITLE:-Omamori Connect IQ developer key}
vault_args=()
if [ -n "${OMAMORI_OP_VAULT:-}" ]; then vault_args=(--vault "$OMAMORI_OP_VAULT"); fi

echo "key:   $key ($(sha256sum "$key" | cut -c1-16)...)"
echo "title: $title${OMAMORI_OP_VAULT:+ (vault $OMAMORI_OP_VAULT)}"

if op item get "$title" "${vault_args[@]}" >/dev/null 2>&1; then
  echo "updating the existing item"
  op document edit "$title" "$key" "${vault_args[@]}" --file-name developer_key.der >/dev/null
else
  op document create "$key" --title "$title" --file-name developer_key.der \
    --tags omamori,connect-iq "${vault_args[@]}" >/dev/null
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
chmod 700 "$tmp"
op document get "$title" "${vault_args[@]}" --out-file "$tmp/check.der" >/dev/null
if cmp -s "$key" "$tmp/check.der"; then
  echo "saved to 1Password and verified (download matches the local key)"
else
  echo "the copy in 1Password does not match the local key; keep the local file" >&2
  exit 1
fi

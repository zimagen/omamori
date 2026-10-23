#!/bin/bash
# Back up the Connect IQ developer key (needed to publish store updates) to
# 1Password as a document item, then download it again and compare.
#
# Usage: scripts/save-key-1password.sh [--vault NAME] [--archive-others] [key.der]
#   --vault NAME       target vault, searched in every signed-in account; the
#                      name matches exactly, else ignoring case, spaces, "-"
#                      and "_". Default: your default vault.
#   --archive-others   after a verified save, move copies of this item in
#                      other vaults to the 1Password archive (recoverable).
#   OMAMORI_OP_TITLE   item title (default: "Omamori Connect IQ developer key")
set -euo pipefail

want_vault=${OMAMORI_OP_VAULT:-}
archive_others=0
key=
while [ $# -gt 0 ]; do
  case "$1" in
    --vault) want_vault=${2:?--vault needs a name}; shift 2 ;;
    --archive-others) archive_others=1; shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) key=$1; shift ;;
  esac
done

if [ -z "$key" ]; then
  for candidate in "$HOME/Documents/omamori-key/developer_key.der" \
                   "$HOME/Work/.omamori-key-transfer/developer_key.der"; do
    if [ -f "$candidate" ]; then key=$candidate; break; fi
  done
fi
if [ -z "$key" ] || [ ! -f "$key" ]; then
  echo "developer key not found; pass its path as an argument" >&2
  exit 1
fi
if ! command -v op >/dev/null; then
  echo "1Password CLI (op) not found. Install 1password-cli and enable" >&2
  echo "Settings > Developer > Integrate with 1Password CLI in the app." >&2
  exit 1
fi
if ! command -v jq >/dev/null; then
  echo "jq not found" >&2
  exit 1
fi
if [ "$archive_others" = 1 ] && [ -z "$want_vault" ]; then
  echo "--archive-others needs --vault" >&2
  exit 1
fi

title=${OMAMORI_OP_TITLE:-Omamori Connect IQ developer key}
norm() { tr '[:upper:]' '[:lower:]' | tr -d ' _-'; }
accounts() { op account list --format json | jq -r '.[].account_uuid'; }

target_account=
target_vault=
args=()
if [ -n "$want_vault" ]; then
  want_norm=$(printf '%s' "$want_vault" | norm)
  exact=()
  loose=()
  seen=()
  while IFS= read -r account; do
    while IFS=$'\t' read -r vid vname; do
      seen+=("$vname  (account $account)")
      if [ "$vname" = "$want_vault" ]; then exact+=("$account"$'\t'"$vid"$'\t'"$vname"); fi
      if [ "$(printf '%s' "$vname" | norm)" = "$want_norm" ]; then loose+=("$account"$'\t'"$vid"$'\t'"$vname"); fi
    done < <(op vault list --account "$account" --format json | jq -r '.[] | [.id, .name] | @tsv')
  done < <(accounts)
  if [ ${#exact[@]} -eq 1 ]; then
    match=${exact[0]}
  elif [ ${#exact[@]} -eq 0 ] && [ ${#loose[@]} -eq 1 ]; then
    match=${loose[0]}
  else
    echo "vault \"$want_vault\": ${#exact[@]} exact and ${#loose[@]} similar matches. Vaults found:" >&2
    printf '  %s\n' "${seen[@]}" >&2
    exit 1
  fi
  IFS=$'\t' read -r target_account target_vault vault_name <<<"$match"
  args=(--account "$target_account" --vault "$target_vault")
  echo "vault: $vault_name (account $target_account)"
fi

echo "key:   $key ($(sha256sum "$key" | cut -c1-16)...)"
echo "title: $title"

if op item get "$title" "${args[@]}" >/dev/null 2>&1; then
  echo "updating the existing item"
  op document edit "$title" "$key" "${args[@]}" --file-name developer_key.der >/dev/null
else
  op document create "$key" --title "$title" --file-name developer_key.der \
    --tags omamori,connect-iq "${args[@]}" >/dev/null
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
chmod 700 "$tmp"
op document get "$title" "${args[@]}" --out-file "$tmp/check.der" >/dev/null
if ! cmp -s "$key" "$tmp/check.der"; then
  echo "the copy in 1Password does not match the local key; nothing archived" >&2
  exit 1
fi
echo "saved to 1Password and verified (download matches the local key)"

if [ "$archive_others" = 1 ]; then
  while IFS= read -r account; do
    while IFS=$'\t' read -r iid ivid ivname; do
      if [ "$account" = "$target_account" ] && [ "$ivid" = "$target_vault" ]; then continue; fi
      op item delete "$iid" --account "$account" --archive
      echo "archived the copy in vault $ivname (account $account); restore it from Archive if needed"
    done < <(op item list --account "$account" --format json \
               | jq -r --arg t "$title" '.[] | select(.title == $t) | [.id, .vault.id, .vault.name] | @tsv')
  done < <(accounts)
fi

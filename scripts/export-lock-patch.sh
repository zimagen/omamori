#!/bin/bash
# Dev helper: commit the local lock-screen changes in ~/omarchy on branch
# local/auth and export them as a patch into contrib/. Touches only ~/omarchy's
# git history (repo-local identity) and contrib/ in this repository.
set -euo pipefail
OM=${OMARCHY_PATH:-$HOME/omarchy}
OUT="$(cd "$(dirname "$0")/.." && pwd)/contrib/0001-howdy-lock.patch"
mkdir -p "$(dirname "$OUT")"
cd "$OM"
git config user.name >/dev/null || git config user.name "zimagen"
git config user.email >/dev/null || git config user.email "zimagen@users.noreply.github.com"
if [[ $(git branch --show-current) != local/auth ]]; then
  git switch local/auth 2>/dev/null || git switch -c local/auth
fi
if ! git diff --quiet; then
  git commit -am "Local: howdy face auth on lock screen"
fi
git format-patch -1 --stdout > "$OUT"
echo "== branch: $(git branch --show-current)"
git log --oneline -2
echo "== patch: $OUT ($(wc -l < "$OUT") lines)"
git status -s | head -5

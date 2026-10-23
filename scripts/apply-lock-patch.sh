#!/bin/bash
# Dev helper: apply contrib/0002 (omamori watch stack) onto ~/omarchy local/auth
# and regenerate the lock-screen PAM files. Does not lock the screen.
set -euo pipefail
PATCH="$(cd "$(dirname "$0")/.." && pwd)/contrib/0002-omamori-watch-lock.patch"
OM=${OMARCHY_PATH:-$HOME/omarchy}
cd "$OM"
# Clean up an interrupted `git am` (e.g. one that waited on stdin).
if [[ -d .git/rebase-apply ]]; then git am --abort; fi
[[ $(git branch --show-current) == local/auth ]] || { echo "not on local/auth" >&2; exit 1; }
if git log --format=%s -20 | grep -qx "Local: omamori watch unlock on lock screen"; then
  echo "patch already applied"
else
  git am "$PATCH"
fi
git log --oneline -3
omarchy-apply-lock
echo "== /etc/pam.d/omarchy-lock-watch"
cat /etc/pam.d/omarchy-lock-watch

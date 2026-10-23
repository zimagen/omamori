#!/bin/bash
# Dev helper: apply the omamori lock-screen patches (contrib/0002, 0003, ...)
# onto ~/omarchy local/auth, skipping ones already applied, then regenerate
# the lock-screen PAM files. Does not lock the screen.
set -euo pipefail
CONTRIB="$(cd "$(dirname "$0")/.." && pwd)/contrib"
OM=${OMARCHY_PATH:-$HOME/omarchy}
cd "$OM"
# Clean up an interrupted `git am` (e.g. one that waited on stdin).
if [[ -d .git/rebase-apply ]]; then git am --abort; fi
[[ $(git branch --show-current) == local/auth ]] || { echo "not on local/auth" >&2; exit 1; }
# Read the log once: `git log | grep -q` under pipefail fails with SIGPIPE when
# grep exits early, which made applied patches look missing.
applied=$(git log --format=%s -50)
for patch in "$CONTRIB"/0[0-9][0-9][0-9]-omamori-*.patch; do
  subject=$(sed -n 's/^Subject: \[PATCH\] //p' "$patch" | head -1)
  if grep -qxF "$subject" <<<"$applied"; then
    echo "already applied: $subject"
  else
    git am "$patch"
  fi
done
git log --oneline -4
omarchy-apply-lock
echo "== /etc/pam.d/omarchy-lock-watch"
cat /etc/pam.d/omarchy-lock-watch
echo "Log out and back in so omarchy-shell reloads the lock screen."

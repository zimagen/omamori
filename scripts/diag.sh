#!/bin/bash
# Dev helper: collect omamori diagnostics into one block of output.
cd "$(dirname "$0")/.."
export SYSTEMD_PAGER= PAGER=cat
echo "== status"; omamori status
echo "== binary (built vs installed)"; sha256sum target/release/omamorid /usr/bin/omamorid 2>&1
echo "== omamorid log"; sudo journalctl -u omamorid -b --no-pager -o short-precise | tail -40
echo "== bluetooth log"; sudo journalctl -u bluetooth -b --no-pager -o short-precise | tail -20
echo "== adapter"; sudo btmgmt info 2>&1 | head -20

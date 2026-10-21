#!/bin/bash
# Dev helper: install freshly built binaries and restart omamorid.
# Does not touch /etc/pam.d.
set -euo pipefail
cd "$(dirname "$0")/.."
sudo systemctl stop omamorid || true
sudo install -Dm755 target/release/omamorid /usr/bin/omamorid
sudo install -Dm755 target/release/omamori /usr/bin/omamori
sudo install -Dm755 target/release/libpam_omamori.so /usr/lib/security/pam_omamori.so
sudo install -Dm644 packaging/omamorid.service /etc/systemd/system/omamorid.service
sudo systemctl daemon-reload
sudo systemctl start omamorid
sleep 2
echo "omamorid: $(systemctl is-active omamorid)"
sha256sum target/release/omamorid /usr/bin/omamorid

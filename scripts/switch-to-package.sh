#!/bin/bash
# Dev helper: replace the hand-installed files (scripts/dev-install.sh) with the
# package built by `makepkg` in packaging/. Overwrites only omamori's own files.
# Does not touch /etc/pam.d.
set -euo pipefail
cd "$(dirname "$0")/../packaging"
pkg=$(ls -t omamori-[0-9]*-x86_64.pkg.tar.* 2>/dev/null | head -1)
[[ -n $pkg ]] || { echo "no built package in packaging/; run makepkg first" >&2; exit 1; }
echo "== installing $pkg"
sudo pacman -U --noconfirm \
  --overwrite /usr/bin/omamori \
  --overwrite /usr/bin/omamorid \
  --overwrite /usr/lib/security/pam_omamori.so \
  "$pkg"
# The hand-installed unit in /etc shadows the packaged one in /usr/lib.
if [[ -f /etc/systemd/system/omamorid.service ]]; then
  sudo systemctl disable omamorid
  sudo rm /etc/systemd/system/omamorid.service
fi
sudo systemctl daemon-reload
sudo systemctl enable omamorid
sudo systemctl restart omamorid
sleep 2
echo "omamorid: $(systemctl is-active omamorid)"
echo "unit: $(systemctl show -p FragmentPath --value omamorid)"
pacman -Qo /usr/bin/omamorid /usr/bin/omamori /usr/lib/security/pam_omamori.so
grep -n '# omamori' /etc/pam.d/sudo || echo "(no omamori line in /etc/pam.d/sudo)"

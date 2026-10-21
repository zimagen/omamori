# omamori

`omamori status` displays daemon status. `sudo omamori pair` displays the
watch's code and asks `Do the codes match? [y/N]`; only explicit acceptance
confirms pairing. `sudo omamori unpair` removes the pairing. Use
`--socket PATH` with any of these commands to select another daemon socket.

`sudo omamori setup-pam` shows a unified diff and asks before adding the
marked module line before the first `auth` or `-auth` line in
`/etc/pam.d/sudo`. `--yes` accepts the displayed edit; `--undo` removes only
lines ending in `# omamori`. Repeated installation is idempotent. Changes
preserve file mode and owner, create a timestamped backup, and atomically
replace the file in its directory.

For tests, `--file PATH` permits an explicit writable file without root,
and the hidden `--skip-module-check` bypasses the installed-module check.
No PAM configuration is edited by the test suite outside temporary files.

# omamori

`omamori status` displays daemon status. `omamori status --json` prints
the exact daemon status fields as one JSON object (without the IPC `ev` tag).
If the daemon cannot be reached, JSON mode prints `{"daemon":false}` and
exits 0; plain status exits 1. `sudo omamori pair` displays the
watch's code and asks `Do the codes match? [y/N]`; only explicit acceptance
confirms pairing. `sudo omamori unpair` removes the pairing. Use
`--socket PATH` with any of these commands to select another daemon socket.

`omamori boost` extends fast BLE advertising for the configured boost window
(default 30 seconds) when your uid has a pending request; root can boost any
pending request. It prints nothing and exits 0 on success, or exits 1 with
the daemon reason on failure. Connection and response timeouts are 200 ms.

`sudo omamori setup-pam` shows a unified diff and asks before adding the
marked module line after `pam_howdy.so` if present, otherwise before the
first `auth` or `-auth` line in
`/etc/pam.d/sudo`. `--yes` accepts the displayed edit; `--undo` removes only
lines ending in `# omamori`. Repeated installation is idempotent. Changes
preserve file mode and owner, create a timestamped backup, and atomically
replace the file in its directory.

For tests, `--file PATH` permits an explicit writable file without root,
and the hidden `--skip-module-check` bypasses the installed-module check.
No PAM configuration is edited by the test suite outside temporary files.

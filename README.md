# Omamori

Unlock sudo and the Omarchy Quattro lock screen with a Garmin Venu 4.
Launch the watch app with a button shortcut: sudo requests show the command
and terminal and require a tap; lock requests are approved automatically
with the default `per-type` policy. Password authentication remains available.
The PC and watch communicate directly over Bluetooth LE; no phone or cloud
service is involved.

The repository includes a root daemon, PAM module, CLI, Connect IQ watch
app, lock-screen patches, and an Omarchy bar widget. The widget polls status
every five seconds while visible. Its watch icon is dimmed when the daemon
is down or unpaired, normal when paired and idle, and active while advertising
or requests are pending. Click it to see status and launch pairing or
unpairing in a floating terminal. Pending requests are scoped to the querying
user by the daemon; root sees all requests.

## Security and requirements

**Enable the watch's system passcode and wrist-removal lock.** The watch
replaces a password, and its shared key lives in plain Connect IQ app storage.
On a real Venu 4, a passcode-locked watch was verified not to enter USB MTP
mode, so that storage cannot be read over USB without the passcode. Physical
flash extraction and debug interfaces are outside this protection.

Pairing uses numeric comparison: accept only if the codes on both devices
match. Authenticated request lists and approvals bind the displayed request
contents; an approval authorizes one request. The default `per-type` policy
requires confirmation for sudo. Changing `approval` to `auto` in
`/etc/omamori/config.toml` also makes sudo approvals automatic. **Risk of
`auto`:** a process running as you can start `sudo` in the background and
leave it waiting; your next button hold then approves it without showing the
command. One hold still approves at most one request. See
[DESIGN.md](DESIGN.md) for the protocol and complete threat model.

Out of scope: BLE relay attacks, proximity unlock, login/TTY authentication,
polkit, LUKS, phone relay, iOS, and multiple watches per PC. User malware must
still obtain an explicit watch approval for sudo under the default policy;
always check the command and terminal shown on the watch.

Requirements and external dependencies:

- Garmin Venu 4 (41 mm or 45 mm), Connect IQ API 5.1 or newer.
- Arch Linux with Omarchy Quattro / omarchy-shell for the widget and lock
  integration; a Bluetooth LE adapter capable of BlueZ GATT peripheral
  operation and advertising.
- Runtime: BlueZ (`bluez`), D-Bus (`dbus`), Linux-PAM (`pam`), and `glibc`.
  systemd manages the daemon. The widget uses Quickshell with Qt Quick,
  `Quickshell.Io`, the Omarchy shell UI modules, its icon font, and
  `omarchy-launch-floating-terminal-with-presentation`.
- Host build: Cargo/Rust meeting the workspace's minimum version (currently
  1.99.0), and Arch build tools (`base-devel`, including the C linker).
- Watch builds: Garmin Connect IQ SDK, Java, and a developer signing key;
  see [watch/README.md](watch/README.md). USB sideloading needs an MTP client.
  Howdy is optional and only relevant to the face-authentication base patch.

## Install

Clone this repository and build the package from its local source tree:

```sh
cd packaging
makepkg -si
cd ..
sudo systemctl enable --now omamorid.service
```

[packaging/PKGBUILD](packaging/PKGBUILD) builds the daemon, CLI and PAM module
with `cargo build --release --locked`. Keep the complete checkout around
`packaging/`; this PKGBUILD intentionally has no downloaded source archive.
Package installation does not edit `/etc/pam.d`.

Sideload the device-specific watch `.prg` into `GARMIN/APPS` over USB MTP,
or install the Omamori app from the Connect IQ store if a release is available.
Build and sideload instructions are in [watch/README.md](watch/README.md).
Assign Omamori to a button hold under **Settings > System > Shortcuts**.

Start pairing on the PC, then launch the watch app (or select **Pair PC**
from its menu if it already has a saved PC):

```sh
sudo omamori pair
```

Compare the six-digit codes and explicitly accept on both devices. Then
configure sudo:

```sh
sudo omamori setup-pam
```

This shows a diff and asks before writing. It inserts a marked PAM line
after `pam_howdy.so` if present, otherwise before the first authentication
line. It preserves permissions and creates a timestamped backup. Password
fallback remains available: a password typed at the Omamori prompt jumps
straight to the password module (`cred_insufficient=N` skips the N auth lines
in between, such as fingerprint), so it is not delayed by other prompts.
Running `setup-pam` again upgrades an older Omamori line.

Security issues: see [SECURITY.md](SECURITY.md).

Install the optional widget, replacing `<repo>` with this repository's URL
or local checkout path:

```sh
omarchy plugin add <repo>
```

The plugin ID is `io.github.zimagen.omamori`; its default bar section is
`right`. Use `omamori status` for a human-readable report or
`omamori status --json` for the daemon's status fields as a single JSON
object. If the daemon cannot be reached, JSON mode prints `{"daemon":false}`
and exits successfully; plain status exits with an error.

Optional daemon configuration lives in `/etc/omamori/config.toml`; missing
configuration uses defaults. Pairing state is root-only at
`/var/lib/omamori/state.json`. See [DESIGN.md](DESIGN.md) for configuration
keys and IPC behavior.

## Lock screen

Watch unlock requires the patches in [contrib/](contrib/) on top of
`omarchy.lock` in an Omarchy Quattro checkout. `0001-howdy-lock.patch` is the
author's Howdy face-authentication base; `0002-omamori-watch-lock.patch`
adds the separate watch PAM stack alongside the other authentication paths;
`0003-omamori-lock-boost.patch` runs `omamori boost` when the lock screen
wakes, so the PC advertises fast again (30 s) and the watch connects quickly.
Apply them in order, or skip 0001 if the matching base is already present.
CI applies all three to the Omarchy commit pinned as `OMARCHY_REF` in
[.github/workflows/lint.yml](.github/workflows/lint.yml). Check your Omarchy
checkout and local modifications before applying patches.

With `OMARCHY_PATH` set to your Omarchy checkout and `OMAMORI_REPO` set to
this checkout's absolute path:

```sh
git -C "$OMARCHY_PATH" am "$OMAMORI_REPO/contrib/0001-howdy-lock.patch"
git -C "$OMARCHY_PATH" am "$OMAMORI_REPO/contrib/0002-omamori-watch-lock.patch"
git -C "$OMARCHY_PATH" am "$OMAMORI_REPO/contrib/0003-omamori-lock-boost.patch"
omarchy-apply-lock
```

Log out and back in afterwards so the shell reloads the lock screen.

The generated `/etc/pam.d/omarchy-lock-watch` runs `pam_omamori.so mode=lock`.
If watch unlock causes trouble, switch to a TTY and disable that stack:

```sh
sudo rm /etc/pam.d/omarchy-lock-watch
```

Password unlock remains available. `omarchy-apply-lock` can recreate the
watch stack while the module is installed.

## Removal and recovery

Remove the integrations before uninstalling the PAM module:

```sh
omarchy plugin remove io.github.zimagen.omamori
sudo rm -f /etc/pam.d/omarchy-lock-watch
sudo omamori setup-pam --undo
sudo omamori unpair
sudo systemctl disable --now omamorid.service
sudo pacman -R omamori
```

Also remove the saved PC on the watch under **Paired PCs > Delete pairing**,
then uninstall the watch app if desired. If you applied the lock patches,
revert 0002 and then 0001 in your Omarchy checkout if those changes are no
longer wanted; preserve any other local changes. Package removal keeps the
root-only state directory for the administrator to manage.

If sudo authentication breaks, switch to a TTY and log in as root. Edit
`/etc/pam.d/sudo` and remove only lines ending in `# omamori`. Backups are
at `/etc/pam.d/sudo.omamori-bak.*`; inspect them before restoring so you do
not overwrite later unrelated edits. The installed Omamori line starts with
`-auth`, which lets sudo keep working if the PAM module disappears. Package
hooks print instructions and warnings only; they never edit PAM files.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
```

The protocol and host integration tests run without Bluetooth hardware.
QML rendering, floating-terminal actions, watch behavior, and lock-screen
integration need an Omarchy Wayland session and hardware testing.

CI (`.github/workflows/`):

- `rust.yml`: fmt, clippy, tests, release build checks (no fake transport,
  PAM module exports only `pam_sm_*`), reproducible test vectors.
- `lint.yml`: shellcheck, actionlint, Omarchy's plugin validator, and the
  `contrib/` lock-screen patches applied and tested against the pinned
  Omarchy commit (`OMARCHY_REF`; bump it together with the patches).
- `package.yml`: `makepkg` in an Arch container; uploads the package.
- `watch.yml`: manual. Builds the watch app (and optionally the store `.iq`).
  Needs secrets `GARMIN_USERNAME`, `GARMIN_PASSWORD`, `CIQ_DEVELOPER_KEY_B64`
  and the variable `CIQ_AGREEMENT_HASH`.

Licensed under the [MIT License](LICENSE).

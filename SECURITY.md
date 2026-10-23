# Security policy

Omamori takes part in sudo and lock-screen authentication, so security
reports are welcome and handled first.

## Reporting a vulnerability

Please report privately through GitHub:
**Security > Report a vulnerability** on
<https://github.com/zimagen/omamori/security/advisories/new>.
Do not open a public issue for anything that could let someone
authenticate without the paired watch, bypass the watch approval, read the
pairing key, or lock the owner out.

Include the affected component (PAM module, daemon, CLI, watch app, lock
screen patch), versions (`pacman -Q omamori`, watch app version, Omarchy
commit), and steps to reproduce. Expect a first reply within 7 days.

## Supported versions

Only the latest release and `main` receive fixes.

## Scope

In scope: the PAM module and its PAM lines, the daemon and its IPC, the
BLE protocol and pairing, the watch app, and the `contrib/` lock-screen
patches.

Out of scope, by design (see [DESIGN.md](DESIGN.md)): BLE relay attacks,
attackers with physical flash access to an unlocked watch, login/TTY,
polkit and LUKS, and sudo requests approved while `approval = "auto"` is set
(documented in the README).

## Recovery if authentication breaks

From a TTY or another root shell:

```sh
sudo omamori setup-pam --undo
sudo rm -f /etc/pam.d/omarchy-lock-watch
```

Password authentication stays available in both stacks.

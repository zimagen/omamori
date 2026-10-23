# pam-omamori

Builds `libpam_omamori.so`; install it as
`/usr/lib/security/pam_omamori.so`. `omamori setup-pam` inserts the sudo
configuration line. The module requires `mode=sudo` or `mode=lock`.
Optional arguments are `socket=PATH`, `tty=PATH`, `timeout=SECONDS`
(sudo, default 300), and `debug` (LOG_AUTHPRIV; never logs passwords).
Unknown arguments are ignored.

Sudo mode races watch approval against terminal password entry, returning
PAM_IGNORE on fallback. Enter copies the password into PAM_AUTHTOK and
returns PAM_CRED_INSUFFICIENT on success, letting the setup-pam control skip
fingerprint modules. The following password module needs `try_first_pass` to consume it. If that
module does not consume the token, it can prompt again normally. Input is
bounded to 4096 bytes; overflow falls back without passing a truncated token.
Lock mode uses only IPC and returns PAM_AUTHINFO_UNAVAIL on failure.

All unsafe ABI and terminal operations live in `src/ffi.rs`. The input loop
and policy live in `src/auth.rs`. Terminal restoration uses a drop guard;
password storage is zeroized, including edited bytes, without reallocating.

Tests use libpam's `pam_start_confdir`, a temporary service directory,
pam_deny, a PTY, the daemon's fake transport, and the reference watch.
A tiny C test module captures PAM_AUTHTOK within the PAM stack because
libpam clears it before returning to applications. A C compiler and the
PAM development headers/library are required. SIGINT is tested in a child
process; the ignored child entry point is invoked by the parent test.

```sh
. ~/.local/sysroot/env.sh
cargo test --workspace --all-features
```

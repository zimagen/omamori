# Omamori — design (v1)

Unlock `sudo` and the Omarchy Quattro lock screen with a Garmin Venu 4.
Password authentication always keeps working; the watch is an alternative,
never a requirement.

## Threat model (decided)

- Watch replaces the password. No app PIN on the watch; the watch system
  passcode (locks when removed from wrist) protects the device. The shared key
  is stored in plain Connect IQ app storage. If on-device testing shows that
  app storage is readable over USB while the watch is passcode-locked, we go
  back to an app-PIN design (out of scope for v1).
  Verified on a Venu 4: a passcode-locked watch does not enter MTP mode, so
  app storage is not reachable over USB without the passcode. Not covered:
  hardware-level extraction (flash chip-off, debug interfaces).
- Out of scope: login/tty, polkit, LUKS, phone relay, proximity unlock, iOS,
  several watches per PC, relay attacks over BLE.
- Malware running as the user must not be able to get root through omamori:
  sudo approvals show the command and tty on the watch and need a tap; one
  approval authorises exactly one request.
- A forged "PC" must not be able to make the watch approve something other
  than what it displays: every request list is MACed by the paired PC and
  every approval MAC binds the exact request contents.

## Components

```
crates/omamori-proto   wire codec, framing, crypto, sans-IO host + watch state machines
crates/omamori-daemon  omamorid: root system service, IPC server, request queue, BLE (bluer)
crates/pam-omamori     libpam_omamori.so (cdylib), modes: sudo | lock
crates/omamori-cli     omamori: pair, unpair, status, setup-pam [--undo]
watch/                 Connect IQ app (Monkey C)
contrib/               lock-screen patch for omarchy.lock
packaging/             systemd unit, PKGBUILD
manifest.json, *.qml   omarchy-shell plugin (status bar widget + panel)
```

## Files on the host

| Path | Owner/mode | Content |
|---|---|---|
| `/etc/omamori/config.toml` | root 0644 | config (below); missing file = defaults |
| `/var/lib/omamori/state.json` | root 0600, dir 0700 | host_id, pairing (watch name, key, time) |
| `/run/omamori/omamori.sock` | root, socket 0666, dir 0755 | IPC |
| `/usr/lib/security/pam_omamori.so` | root 0755 | PAM module |

config.toml:

```toml
approval = "per-type"   # "per-type" (lock = auto, sudo = confirm on watch) | "auto"
host_name = ""          # empty = hostname
adapter = ""            # empty = default BlueZ adapter
adv_interval_ms = [20, 30] # min/max, each 20..=10240 ms, min <= max
sudo = true
lock = true
```

state.json is written atomically (tmp + fsync + rename). host_id (16 random
bytes) is created once and survives re-pairing; re-pairing replaces the key.
`omamori unpair` deletes the pairing (key rotation = unpair + pair).

## IPC (Unix stream socket, JSON lines, max line 4 KiB)

The daemon identifies the peer with SO_PEERCRED and ignores identity claims
in messages.

client → daemon

- `{"op":"request","kind":"sudo","user":U,"command":C,"tty":T,"pid":P}` —
  accepted only from uid 0.
- `{"op":"request","kind":"lock","user":U}` — any uid; `U` must equal the
  peer uid's user name, otherwise denied. Root may not send lock requests.
- `{"op":"status"}` — any uid. Returns paired (bool), watch_name, host_name,
  adapter_powered, advertising, and the pending requests *of the peer's own
  uid* (root sees all).
- `{"op":"pair-begin"}`, `{"op":"pair-confirm","accept":bool}`,
  `{"op":"unpair"}` — uid 0 only.

daemon → client

- `{"ev":"queued","id":"<16 hex>"}`
- `{"ev":"approved"}` (then the daemon closes the connection)
- `{"ev":"unavailable","reason":"not-paired"|"disabled"|"no-adapter"|"busy"}`
- `{"ev":"denied","reason":...}`
- pairing: `{"ev":"pair-code","code":"123456","watch_name":...}`,
  `{"ev":"pair-done"}`, `{"ev":"pair-failed","reason":...}`
- `{"ev":"status",...}`

A request lives exactly as long as its client connection. Disconnect =
cancel. Limits: 4 pending requests per uid, 16 total; sudo fields truncated
(command 256 bytes, tty 32). Malformed input closes the connection.

## BLE

The PC is the GATT peripheral (Connect IQ is central-only).

- Service UUID `4f6d616d-6f72-6900-0001-000000000000`
- RX characteristic `…0002`: write / write-without-response (watch → PC)
- TX characteristic `…0003`: notify (PC → watch)
- Advertising only while ≥1 request is pending or pairing is active.
  Service data (for the service UUID): `host_id[0..8] || flags u8`
  (bit0 = pairing mode). The watch selects its stored key by that prefix.
  Advertising data contains only the service-data AD for the service UUID
  (30 bytes incl. flags); the UUID is not listed separately.
  Advertising intervals default to 20–30 ms, configurable with
  `adv_interval_ms`. These parameters do not consume advertising payload bytes.
  If BlueZ rejects registration with intervals, the daemon warns and retries
  once using BlueZ defaults, remembering this fallback until restart. It logs
  the selected interval mode once; BlueZ may silently ignore interval settings.
  In authentication mode, the watch connects immediately when its only saved
  host is discovered. With multiple saved hosts, or in pairing mode, it collects
  candidates for 1200 ms before connecting or showing the host chooser.
- One connection at a time; session state resets on disconnect; session
  idle timeout 60 s; pairing timeout 120 s.

### Framing

Each GATT write/notification carries one chunk of at most `chunk` bytes
(default 20, matching the ATT default MTU of 23). Chunk = header byte + data;
header bit7 = last chunk of a message, bits 0–6 = sequence number mod 128,
starting at 0 for each message. Max reassembled message 1024 bytes. An out of
order sequence or oversize message resets the session.

### Messages

All integers are big-endian. `str` = u8 length + UTF-8 bytes (≤ 255, cut on
a char boundary). Each message starts with `ver u8 = 1`, `type u8`.
`K` = 32-byte shared key. `H` = SHA-256, `MAC` = HMAC-SHA256.
Domain-separation labels are ASCII without terminator.

Watch → PC

| type | name | body |
|---|---|---|
| 0x01 | AuthHello | watch_nonce[16] |
| 0x02 | Approve | req_id[8], mac[32] |
| 0x10 | PairCommit | commit[32] |
| 0x11 | PairReveal | watch_pub[65], watch_nonce[16], watch_name str |
| 0x12 | PairConfirm | accepted u8, mac[32] |

PC → Watch

| type | name | body |
|---|---|---|
| 0x81 | Pending | host_id[16], host_name str, more u8, count u8, entries…, mac[32] |
| 0x82 | Result | req_id[8], status u8, mac[32] |
| 0x90 | PairHost | host_pub[65], host_nonce[16], host_id[16], host_name str |
| 0x91 | PairResult | accepted u8, mac[32] |
| 0xFF | Error | code u8 (1 not paired, 2 bad mac, 3 unknown request, 4 protocol) |

Pending entry: `req_id[8], kind u8 (1 lock, 2 sudo), flags u8 (bit0
needs_confirm), age_s u16, title str, detail str`.

Size rule: on the wire title is truncated to 48 bytes and detail to 160
bytes (char boundary). The host lists requests oldest first and stops before
the entry that would make the message exceed 1024 bytes; Pending flags in a
header byte after host_name: `more u8` (1 if entries were left out). The
watch shows "+ more" and a refresh lists the rest once earlier ones are gone.
Wire layout therefore is: `host_id[16], host_name str, more u8, count u8,
entries…, mac[32]`.

MACs:

- Pending: `MAC(K, "omamori/v1/pending" || watch_nonce || <all message bytes before mac>)`
- Approve: `MAC(K, "omamori/v1/approve" || host_id || watch_nonce || req_id || kind || H(u16len(title) || title || u16len(detail) || detail))`
  where title/detail are the exact wire (possibly truncated) bytes and
  `u16len` is the byte length as big-endian u16.
- Result: `MAC(K, "omamori/v1/result" || watch_nonce || req_id || status)`;
  status 0 ok, 1 unknown/expired, 2 bad mac.

The daemon accepts an Approve only for a req_id it listed in a Pending
message sent during the *current* session, still pending, with a valid MAC
(constant-time compare). Each request can be approved once. A bad MAC
closes the session and is logged.

### Watch behaviour (reference: `omamori-proto::watch`)

1. Scan for the service; match service-data prefix to a stored host_id; if
   several match, let the user choose. Connect, enable TX notifications,
   send AuthHello with a fresh nonce.
2. Verify the Pending MAC; reject otherwise.
3. If any entry has needs_confirm = 0: approve the oldest such entry without
   asking. Then, if entries with needs_confirm = 1 remain, show them.
4. Entries with needs_confirm = 1 are shown (title, detail) and approved
   only by an explicit tap, one per tap. To refresh, send a new AuthHello.

The daemon sets needs_confirm = 1 for sudo and 0 for lock when
`approval = "per-type"`, and 0 for everything when `approval = "auto"`.

### Pairing (numeric comparison with commitment)

1. `sudo omamori pair` → daemon enters pairing mode, advertises with the
   pairing flag.
2. Watch (pair mode) → PairCommit: `commit = H("omamori/v1/commit" || watch_pub || watch_nonce)`.
3. PC → PairHost (fresh P-256 key pair and nonce).
4. Watch → PairReveal. PC checks the commitment.
5. Both compute
   - `z` = ECDH x-coordinate (32 bytes)
   - `K = HKDF-SHA256(ikm = z, salt = host_nonce || watch_nonce, info = "omamori/v1/key" || host_id, L = 32)`
   - `th = H(PairCommit || PairHost || PairReveal)` over the full message bytes
   - `code = (u32 from first 4 bytes of MAC(K, "omamori/v1/sas" || th)) mod 1_000_000`, shown as 6 digits.
6. The CLI shows the code and asks y/N; the watch shows the code with
   accept/reject. Watch → PairConfirm(accepted,
   `MAC(K, "omamori/v1/pair-ok/watch" || th || accepted)`). A rejecting
   watch still sends a valid MAC over accepted = 0.
7. When both sides accept and the MAC is valid, the daemon stores the
   pairing and sends PairResult(1, `MAC(K, "omamori/v1/pair-ok/host" || th || 0x01)`);
   the watch stores `{host_id, host_name, K}` only after verifying it.
   Otherwise PairResult(0, zeros) and nothing is stored.

Public keys are SEC1 uncompressed (65 bytes, 0x04 || X || Y).

## PAM module

Line added by `omamori setup-pam` (after pam_howdy.so if present, else at the top of the auth section) of
`/etc/pam.d/sudo`:

```
-auth sufficient pam_omamori.so mode=sudo   # omamori
```

Lock screen service `/etc/pam.d/omarchy-lock-watch`:

```
#%PAM-1.0
auth       required    pam_omamori.so mode=lock
account    include     system-local-login
```

Module arguments: `mode=sudo|lock` (required), `socket=PATH`
(default `/run/omamori/omamori.sock`), `timeout=SECONDS` (sudo: default 300,
then PAM_IGNORE), `tty=PATH` (default `/dev/tty`; for tests), `debug`.

Every failure path (daemon unreachable, not paired, disabled, no tty,
internal error, panic) returns PAM_IGNORE in sudo mode and
PAM_AUTHINFO_UNAVAIL in lock mode, after restoring the terminal. Panics must
not cross the FFI boundary. Passwords are zeroised after use.

### mode=sudo (runs inside sudo as root)

1. Skip (PAM_IGNORE) if PAM_SERVICE is not `sudo`/`sudo-i`, or sudo's argv
   (`/proc/self/cmdline`) contains `-S`/`--stdin`, `-A`/`--askpass`,
   `-n`/`--non-interactive` (including clustered short options before the
   command), or the tty cannot be opened.
2. Send the sudo request (user = PAM_USER, command = argv after sudo's
   options, tty = PAM_TTY, pid). On anything but `queued`, PAM_IGNORE.
3. Print `[omamori] Approve on your watch, or type the password.` and the
   password prompt (`[sudo] password for USER: `, or the PAM conversation's
   prompt text if sudo set `SUDO_PROMPT` in the PAM env).
4. Put the tty in non-canonical, no-echo, no-ISIG mode and `poll` the tty and
   the socket:
   - `approved` → restore the tty, print `approved by watch`, PAM_SUCCESS.
   - Enter → set PAM_AUTHTOK to the typed password, close the socket
     (cancels the request), PAM_IGNORE (pam_unix with try_first_pass checks
     it; on a wrong password sudo prompts normally).
   - VERASE / VKILL / VWERASE handled; VINTR (^C) → restore, newline,
     `raise(SIGINT)`, then PAM_ABORT if still alive; VEOF on an empty line
     → PAM_ABORT.
   - daemon disconnects → keep reading the password (degrade, no watch).
   - timeout → restore, PAM_IGNORE.
5. The terminal state is always restored (including on panic).

### mode=lock (runs inside omarchy-shell as the user)

Send `{"op":"request","kind":"lock","user":PAM_USER}` and block until
`approved` (PAM_SUCCESS) or the connection closes / unavailable
(PAM_AUTHINFO_UNAVAIL). No conversation, no tty. The lock screen aborts the
attempt by killing the PAM child; the daemon sees the disconnect.

## CLI

- `omamori status` — any user.
- `sudo omamori pair` — shows the code, asks y/N.
- `sudo omamori unpair`
- `sudo omamori setup-pam [--undo] [--yes] [--file /etc/pam.d/sudo]` —
  backup to `<file>.omamori-bak.<timestamp>`, insert the marked line right
  after the last `pam_howdy.so` auth line if present (face recognition runs
  first), otherwise before the first `auth` line; idempotent; `--undo` removes only lines carrying the
  `# omamori` marker. Shows the diff and asks before writing.

## Testing without hardware

- `omamori-proto` contains both state machines; tests run full pairing and
  approval through an in-memory link, plus negative tests (bad MAC, wrong
  session nonce, replayed approve, commitment mismatch, oversize/out-of-order
  frames). `test-vectors/v1.json` gives fixed-input vectors for the watch app.
- The daemon's BLE layer sits behind a trait; a fake transport drives the
  watch state machine in tests. Test-only hooks live behind the cargo
  feature `test-harness`, never enabled in release builds.
- The PAM module is tested with `pam_start_confdir` against a temporary
  service directory, a pty passed through `tty=`, and the daemon running with
  the fake transport.

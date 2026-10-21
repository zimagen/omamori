# omamorid

Tokio system daemon for the v1 protocol in `DESIGN.md`. Cryptography, message
encoding, approval validation and pairing state machines live in
`omamori-proto`. This crate supplies private persistent storage, SO_PEERCRED
IPC, request connection lifetimes, session timeouts and BLE peripheral I/O.

Build and run (source the sysroot environment before every Cargo command in
the development container):

```sh
. ~/.local/sysroot/env.sh
cargo build --release -p omamori-daemon
target/release/omamorid --config /etc/omamori/config.toml \
  --state-dir /var/lib/omamori --socket /run/omamori/omamori.sock \
  --transport bluez
```

Install `packaging/omamorid.service` with the binary for systemd operation.
The daemon needs access to the system D-Bus and BlueZ's GATT/LE advertising
APIs. It does not power on an adapter automatically. Missing D-Bus/adapter
leaves IPC available; BLE initialization retries every two seconds. Adapter
power changes update availability.

RX supports writes and writes without response through callbacks. TX uses
BlueZ's device-scoped notification IO; stopping notifications or disconnecting
ends the protocol session. Other centrals cannot write into that session.
Chunks remain at the default 20 bytes, even when an MTU is larger. Advertising
contains the service UUID and the nine-byte service data, with no local name.

The actor owns the queue, pairing owner and session. Before processing an
approval, it removes closed IPC clients and supplies the current queue to the
proto session. A connection owns at most one request. Pair confirmation must
come from the same root connection that began pairing. Pair cancellation,
disconnect or timeout releases ownership. Re-pairing replaces the shared key
while preserving `host_id`.

State is written using a unique 0600 temporary file, fsync, rename and directory
fsync. A private advisory lock prevents concurrent daemons using one state
directory. State directories/files must belong to the effective uid and grant
no group/world access; symlinks are rejected. A live socket or ordinary file
at the configured socket path is preserved; only a stale socket is removed.

## Tests

```sh
. ~/.local/sysroot/env.sh
cargo test --workspace --all-features
```

The `test-harness` feature exposes an in-process channel transport and a policy
that can treat the current test uid as root. Actual IPC identity always comes
from kernel peer credentials. No config or environment variable can override
production authorization. Release builds without the feature reject
`--transport fake`. Integration tests run the reference watch over framed
channels and real Unix sockets. Synthetic uid queue tests cover cross-user
status isolation and the total request limit; time is advanced for timeout tests.

Real BlueZ, D-Bus, Bluetooth hardware, Garmin interoperability and systemd
sandbox operation require host testing. In particular, verify notification IO,
advertisement registration and adapter power cycling on the target BlueZ.

## Choices where DESIGN.md leaves representation unspecified

- State JSON uses byte arrays for `host_id` and `pairing.key`, a nullable
  `pairing` object with `watch_name` and `time` (Unix seconds).
- Unpair acknowledges with `{"ev":"status","paired":false}`.
- RX/TX UUID ellipses mean the final suffixes 0002/0003:
  `4f6d616d-6f72-6900-0001-000000000002` and
  `4f6d616d-6f72-6900-0001-000000000003`.
- Equal integer-second ages use request IDs as the protocol tie-breaker.
  Sudo details put the tty before the command so it survives wire truncation.

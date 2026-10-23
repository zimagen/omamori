# omamori-proto

Transport-independent implementation of the v1 protocol in the repository's
`DESIGN.md`. The library performs no I/O and forbids unsafe Rust.

- `wire`: complete message tables, strict decoding, UTF-8 string truncation.
- `framing`: GATT chunking and bounded reassembly with modulo-128 sequences.
- `crypto`: RustCrypto primitives, secret ownership and v1 MAC/KDF/SAS formulas.
- `host`: PC authentication and pairing sessions.
- `watch`: watch reference authentication and pairing sessions.

## Driving a session

A session's `receive` takes a complete reassembled message. Its `Output` contains
complete outgoing messages and local events. Frame each outgoing message before
sending it. Preserve output order. `receive` errors are fatal; discard the
connection. Also close the connection when `is_closed()` becomes true, after
sending any final output. A bad approval MAC produces an authenticated Result
with status 2 and closes the host session; the transport owner can log this.
Framing errors poison the reassembler and require closing the entire session.

Call `host::Session::set_pending` whenever the authoritative request queue
changes, **before** processing incoming approvals. It atomically replaces the
snapshot and rejects duplicate IDs. Wire strings truncate on encoding, while
original strings remain in the snapshot: even changes beyond the truncation
boundary invalidate prior listing authorization. Removed or changed requests
lose their prior listing authorization. Age changes
alone do not invalidate a listing. IDs must identify one request for their whole
lifetime; never recycle an ID within a connection.

Authentication starts with `watch::Session::authenticated`, which emits
AuthHello. The host answers with Pending. The watch verifies its MAC, approves
one oldest entry that does not require confirmation, and emits `Show` with the
remaining entries that require a tap. Call `tap(id)` only for an actual user tap;
each call approves exactly one displayed entry. Process Result before calling
`refresh` to send another AuthHello with a fresh nonce. Refresh can approve the
next automatic entry. Host snapshots list oldest requests first, using request
IDs to break equal-age ties.
Pending fits 1024 bytes; title/detail limits are 48/160 UTF-8 bytes.
The watch exposes omitted entries through `more()`; refresh after approvals
to retrieve remaining requests. Confirmation MACs authenticate acceptance,
and approval hashes use length-prefixed wire contents.

Pairing starts with `watch::Session::pairing` and `host::Session::pairing`.
Exchange their outputs and display the `PairCode` events. Each UI calls
`confirm_pairing(bool)` once. Only `Paired` events carry a key for storage.
Host and watch sessions close on pairing success; construct new authentication
sessions with the stored key. Failure drops ephemeral and derived secrets.
`Key` redacts Debug output and zeroizes on drop. P-256 private keys and ECDH
shared secrets use RustCrypto's zeroizing types. Callers must protect any key
copies they explicitly make for persistence.

All randomness comes from the supplied `CryptoRng`. Production callers can
use `rand_core::UnwrapErr(getrandom::SysRng)` (with getrandom's `sys_rng`
feature); the deterministic RNG under `tests/common` is only for tests. The
fixed scalars and keys in the vector generator are public fixtures.

The transport owner handles scanning, connection ownership, persistence and
clocks. Drop sessions and reassemblers on disconnect or timeout: 60 seconds of
idle time for authentication, 120 seconds for pairing. Nonce reuse is rejected
within a host session; fresh randomness across connections remains the caller's
responsibility.

## Validation and interoperability

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --offline
cargo run -p omamori-proto --example gen-vectors > test-vectors/v1.json
```

The JSON fixture contains fixed P-256 scalars/public keys, ECDH output, HKDF key,
full pairing messages and transcript hash, SAS, both confirmation MACs, Pending,
Approve, Result and a long Pending framed at chunk size 20. Byte strings use hex;
SAS remains a six-character decimal string. A regression test requires exact,
byte-for-byte regeneration of the checked-in JSON.

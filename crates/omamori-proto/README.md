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
next automatic entry. Host snapshots are encoded in request-ID order, so that
order breaks equal-age ties on the watch.

Pairing starts with `watch::Session::pairing` and `host::Session::pairing`.
Exchange their outputs and display the `PairCode` events. Each UI calls
`confirm_pairing(bool)` once. Only `Paired` events carry a key for storage.
Host and watch sessions close on pairing success; construct new authentication
sessions with the stored key. Failure drops ephemeral and derived secrets.
`Key` redacts Debug output and zeroizes on drop. P-256 private keys and ECDH
shared secrets use RustCrypto's zeroizing types. Callers must protect any key
copies they explicitly make for persistence.

All randomness comes from the supplied `CryptoRngCore`. Production callers can
use `rand_core::OsRng`; the deterministic RNG under `tests/common` is only for
tests. The fixed scalars and keys in the vector generator are public fixtures.

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

## Spec questions and chosen interpretations

1. **PairConfirm's `accepted` byte is outside its MAC.** The wire format and MAC
   formula are implemented exactly as specified. Consequently an active peer
   can flip a watch rejection into acceptance at the host if the host accepted;
   the rejecting watch still stores nothing. Should a future protocol version
   authenticate the acceptance byte, or emit no valid confirmation MAC on
   rejection? PairResult's acceptance byte is likewise outside its MAC (though
   rejection carries a zero MAC, which cannot become a valid acceptance).
2. **The approval contents hash uses a NUL separator without lengths.** Valid
   UTF-8 strings can contain NUL, so distinct title/detail pairs can have the
   same preimage. The codec accepts UTF-8 exactly as specified and the host
   independently checks its exact listed snapshot. Should v1 forbid embedded
   NUL or should a later version hash length-prefixed strings?
3. **A full Pending can exceed 1024 bytes.** No pagination or selection rule is
   specified. Encoding fails with `Oversize`; the host closes the session rather
   than silently dropping requests or sending an oversized message. The caller
   must supply a snapshot that fits a single message.
4. **Multiple automatic entries and equal ages.** The watch approves exactly
   one oldest automatic entry per Pending, using wire order to break age ties.
   A fresh AuthHello refreshes the list. Only entries that require confirmation
   are shown for tapping. No extra automatic approvals are inferred from Result.
5. **Reserved values and session completion.** Unknown entry flag bits,
   non-boolean acceptance bytes, unknown kinds/statuses/error codes are protocol
   errors. Pairing completes the connection; timeouts remain with the I/O owner.

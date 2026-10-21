# Omamori for Venu 4

Connect IQ watch app for **Venu 4 45 mm** (`venu445mm`) and **Venu 4 41 mm**
(`venu441mm`). Requires API 5.1 or newer. The sole permission is
`BluetoothLowEnergy`; the watch talks directly to the PC. The service is
`4f6d616d-6f72-6900-0001-000000000000`; RX/TX end in `000002`/`000003`,
matching the daemon (the design abbreviates these as “...0002”/“...0003”).

## Build

From the repository root, with the Garmin SDK and Java installed:

```sh
. ~/.local/opt/ciq-env.sh
mkdir -p watch/bin
python3 watch/tools/generate_vectors.py --check
monkeyc -d venu445mm -f watch/monkey.jungle -o watch/bin/omamori-venu445mm.prg \
  -y ~/.local/share/omamori-dev/developer_key.der -w
monkeyc -d venu441mm -f watch/monkey.jungle -o watch/bin/omamori-venu441mm.prg \
  -y ~/.local/share/omamori-dev/developer_key.der -w
```

The signing key stays outside the repository. `watch/bin/` is ignored.
To regenerate the committed fixture constants after a fixture update:

```sh
python3 watch/tools/generate_vectors.py
```

## Install and use

Connect the watch over USB, open its storage using an MTP file manager, and
copy the correct device's `.prg` into **GARMIN/APPS**. Disconnect USB and
open **Omamori** from the watch's apps.

Assign Omamori to a button hold at **Settings > System > Shortcuts** on the
watch. With no paired PCs, launching the app goes straight to pairing mode.
Otherwise, it immediately scans for paired PCs and authenticates. A lock request
without confirmation is approved automatically, vibrates briefly on success,
and exits after about 1.5 seconds when there are no remaining requests.

When idle or showing an error, tap the screen or press START to open the menu
for **Pair PC**, **Refresh**, or **Paired PCs**. The menu gesture is also
supported where available. START never confirms pairing or approves a request.
For first pairing, start `sudo omamori pair` on the PC and launch the watch app.
To pair another PC, choose **Pair PC** from the menu.
Compare the six digits on both screens. Tap to accept; Back rejects.
Confirm on the PC too. The watch saves the host only after authenticating its
positive PairResult. Pair rejection is sent with a valid MAC before disconnect.

For sudo, the screen shows the request's title and full command/tty detail.
Swipe to move between pending entries; the counter identifies the current
entry. If the text needs another page, tap **to read more** first; only a tap
on the final page approves that displayed request. Each approval consumes
one request. `+ more` indicates requests omitted from the current wire list;
**Refresh** loads a new authenticated list once outstanding results arrive.
The app also refreshes after draining the visible batch and between automatic
requests. When several PCs are discovered in the initial discovery window,
a menu lets you choose one. The pairing chooser uses advertised names until
the authenticated pairing exchange supplies the host name.

**Paired PCs** lists saved hosts. Select a host and then **Delete pairing**
to remove its local key. This leaves the session before editing storage;
unpair separately on the PC if desired. Host IDs, names and keys are stored
only in `Application.Storage`, with string dictionary keys. No app settings,
Properties, background activity, phone communications, or secret logging are
used. Scanning times out after 15 seconds; connections/sessions after 60.

## Simulator unit tests (run on a host with a display)

Build both test binaries:

```sh
. ~/.local/opt/ciq-env.sh
monkeyc -d venu445mm -f watch/monkey.jungle -o watch/bin/omamori-tests.prg \
  -y ~/.local/share/omamori-dev/developer_key.der -w --unit-test
monkeyc -d venu441mm -f watch/monkey.jungle -o watch/bin/omamori-venu441mm-tests.prg \
  -y ~/.local/share/omamori-dev/developer_key.der -w --unit-test
```

Start the simulator on that host, then run No Evil tests:

```sh
connectiq
monkeydo watch/bin/omamori-tests.prg venu445mm -t
monkeydo watch/bin/omamori-venu441mm-tests.prg venu441mm -t
```

Run the `monkeydo` commands after the simulator is ready. The suite covers
all ten codecs, framing/reassembly and sequence wrap, malformed messages and
UTF-8, exact Pending/Approve/Result MACs, RFC 5869 HKDF, commitment, transcript,
SAS, pairing messages, both ECDH roles, automatic oldest selection, explicit
one-use approval, refresh restrictions, bad MACs, wrong nonce/host, duplicate
IDs/results, rejection, and persistence only after mutual confirmation.
Constants in `source/tests/Vectors.mc` come from `test-vectors/v1.json`;
AuthHello and Error literals supplement the fixture's eight message types.
Test helpers and vectors carry `(:test)` and are excluded from normal builds.

CIQ public keys have little-endian coordinates; the wire uses SEC1
big-endian coordinates. `Crypto.secret()` probes `generateSecret()` once
using the session's ephemeral key: ECDH with the P-256 generator must equal
its own public key's x coordinate. It recognizes either output byte order
and caches the normalization for the app run before HKDF. Unexpected output
fails with “ECDH self-test failed”. Catchable Cryptography exceptions reached
from BLE callbacks fail the session with “Crypto error”. Fixed private-key
imports are restricted to test code.
`testEcdhSimulator` checks raw and normalized secrets against the fixture.
The SDK's `createPublicKey` signature incorrectly names its first parameter
`HashAlgorithm` while its documentation requires a `KEY_PAIR_*` constant;
the wrapper casts the required P-256 constant to satisfy that signature.

The headless development environment built all four binaries and checked
fixture generation. **It did not execute No Evil tests or observe simulator
ECDH output.** Run the commands above to complete runtime verification.
Physical-watch checks remain: BLE discovery/CCCD/write sequencing with the
PC, both watch layouts and touch controls, vibration/button shortcut, and
whether app storage is accessible over USB while the watch is passcode
locked (the DESIGN.md threat-model check).

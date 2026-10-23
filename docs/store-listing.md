# Connect IQ store listing (draft)

Upload: https://apps.garmin.com/developer/ > Upload an App > Watch App,
file `watch/bin/omamori.iq` (built with `monkeyc -e -r`, signed with the
developer key backed up in 1Password).

## Basic information

- App name: Omamori
- Type: Watch App
- Version: 0.1.0
- Category: Tools (Utilities)
- Price: Free
- Devices: Venu 4 41 mm, Venu 4 45 mm (from manifest.xml)
- Languages: English
- Website / support: https://github.com/zimagen/omamori
- Support contact: https://github.com/zimagen/omamori/issues
  (security reports: https://github.com/zimagen/omamori/security/advisories/new)

## Summary (one line)

Approve sudo and unlock your Omarchy Linux lock screen from your watch.

## Description

Omamori turns your Venu 4 into a hardware key for your Linux PC.
Hold a button, and the watch connects to your PC over Bluetooth Low Energy
to approve a pending `sudo` command or unlock the lock screen.

REQUIRES PC SOFTWARE. This app does nothing on its own. Your PC must run
Omarchy (Arch Linux, Hyprland) with the free, open-source Omamori daemon and
PAM module installed from https://github.com/zimagen/omamori. Without it,
the app scans and then shows "No pairing PC nearby".

How it works
- Pair once: run `sudo omamori pair` on the PC, open the app, and confirm
  the same six-digit code on both screens.
- Assign Omamori to a button hold (Settings > System > Shortcuts).
- When sudo or the lock screen asks, hold the button. The watch shows what
  is being approved; lock-screen unlocks go through immediately.
- Your password still works as before; the watch is an extra way in.

Security
- Direct watch-to-PC connection. No phone, no cloud, no account.
- Pairing uses an ECDH key exchange confirmed by a six-digit code; every
  approval is authenticated with HMAC-SHA256 and bound to the request shown.
- The pairing key is stored in the app's storage on the watch. Turn on the
  watch passcode and wrist-detection lock so a lost watch cannot be used.
- Open source (MIT). Threat model and protocol:
  https://github.com/zimagen/omamori/blob/main/DESIGN.md

Permissions
- Bluetooth Low Energy: to scan for and connect to your paired PC. Nothing
  else is sent anywhere; the app collects no data.

Not affiliated with Garmin or Omarchy.

## Notes for the reviewer (if a field exists; otherwise append to the description)

This is a companion app for Linux PC software, so it cannot complete a flow
without a PC running the Omamori daemon. Without one it starts, shows
"Scanning for pairing PC…", then "No pairing PC nearby"; this is expected
and the app exits cleanly with BACK. Source and setup: https://github.com/zimagen/omamori

## Assets

- Store icon: 500 x 500 px PNG, sRGB, solid (not black or transparent)
  background, about 10 px padding, no text: `docs/store/icon-500.png`.
- Screenshots (at least one, PNG with extension, 150 KB max each):
  1. Pairing code screen ("Compare pairing code")
  2. sudo request screen (command and terminal)
  3. Success screen
  4. Menu
- Optional hero image: 1440 x 720 px.

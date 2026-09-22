# LG build 45 parity — 22 September 2026

Source behavior: iOS 3.2.4 (45), commits `02e5e6b`, `6c026ad`, `1ec72a4`.
Authorized scope: port applicable fixes, test, adversarial review, local commits.
No version bump, tag, push, upload or release. Pro/TestFlight entitlements and
the iOS self-test standby correction are deliberately outside this port.

Hardware caveat: no physical LG or platform-device wake test was performed.
Automated, emulator and source evidence below does not establish cold-widget
execution on a phone, TV-visible wake latency, or real-network delivery.

## Behavior and entry points

Power commands distinguish unavailable/pre-registration-drop TVs from explicit
refusal or silent registration. Toggle may wake only the former; explicit off
returns already off/unreachable without wake. Failed off writes never fall back
to wake. Power probes use one second for socket establishment and retain the
normal ten-second registration timeout per mode (at most one unsigned retry).
Explicit `on` still sends WOL directly. Decisions/send counts go to stderr.

Scan now refreshes populated MACs for paired TVs; enrich already replaced guesses.
Unreported fields and pairing data survive. No standalone widget process exists.

## Verification

- `python3 -m unittest discover -s tests`: 20 passed.
- `python3 -m py_compile lgtvremote_cli.py` and CLI --help: passed.
- Regression coverage: exact standby drop, close-before-wake, duplicate MACs,
  rejection and silence for off and toggle, missing MACs, rotated keys, ambiguous
  off write, and scanning over a guessed MAC without clearing the other interface.
  Existing real local socket-frame registration test remains green.
- `/tmp/lg45-cli-tests.log`; no physical LG wake or latency measurement.

## Adversarial review

Checked that refusals cannot become wake or successful off, rejected requests
retain keys, off write failures cannot power the set back up, all opened sockets
close, and a peer Close frame releases the underlying descriptor. Fixed resource
cleanup for failed handshakes and peer closes. Explicit-on now also fails if all
UDP sends fail rather than printing success. No hardware success claims are made.

Final review also covers a failed compatibility reconnect: prior socket-open
evidence survives the retry, so this error cannot be reclassified as asleep.

# Decoder regression tests

The application, native helper, source installer and hpkg build do not require
Python. The native tests also run without it:

```sh
setarch x86 sh tests/run-native.sh
```

Omit `setarch x86` on a non-hybrid system. The tests require a C++11 compiler
and OpenSSL development headers. On macOS, `OPENSSL_PREFIX` can select the
OpenSSL installation; compiler options can be passed to `run-native.sh`.

Tests cover the exact authentication USB transcript, session-key/nonce
validation, a fixed AES vector generated independently with OpenSSL, section
CRC and continuity handling, malformed PMTs, PID filtering, every two-part USB
split, resynchronization, decoder reset, and input limits. They never tune a
receiver or require an antenna.

`fixtures/native_exchange.bin` uses synthetic credentials. Its format is
`R1REPL01`, a 16-byte host secret, a 16-byte host nonce, and a little-endian
32-bit transfer count. Each transfer is `<BBHHHi` (type, request, value,
index, length, result), followed by `length` data bytes. The associated JSON
records the original independent reference exchange. `normalized.ts` is the
expected output from the previous implementation using synthetic TS packets.
No saved broadcast or live session key is included in these fixtures.

The former Python implementation is retained only under `reference/` as an
optional comparison oracle. To run its tests and native IPC integration tests:

```sh
setarch x86 sh decoder/build.sh /tmp/oneseg-decoder
RONESEG_DECODER=/tmp/oneseg-decoder PYTHONPATH=tests/reference \
    python3 -B -m unittest discover -s tests -v
```

The IPC tests deliberately give the native process a `PATH` containing no
interpreter and use a fresh installation directory with no user settings.

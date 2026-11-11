# v7-lite: v7 reduced to the bot widget limit (2026-11-05)

Goal: keep the encrypted PIN loader but fit `zlib.compress(html, 9) <= 4096`
for a single bot-delivered widget. The exact v7 does not fit: its ELF resolver
and context/arena fallbacks push the encrypted loader past 10 KB.

## Result

| component | raw | zlib-9 |
|---|---:|---:|
| payload, minified | 4,205 | 1,988 |
| LZSS-compressed payload | 2,475 | — |
| base64 ciphertext | 3,300 | — |
| **loader with PIN keypad + ChaCha** | **5,627** | **3,942** |

Margin: **154 B** under the 4,096 B bot limit. Raw is far below 32 KiB.
Node roundtrip: `ROUNDTRIP_OK captured=4205 wrongpin=blocked double_ok=no_reentry`.

Files:

- `lab/regexp1827_class64/device_payload_v7lite.js` (source)
- `lab/regexp1827_class64/device_payload_v7lite.min.js` (embedded payload)
- `poc/loader_v7lite_chacha.html` (keypad + ChaCha + LZSS, PIN 19111998)

Build: `c2/tools/make_loader_keypad_chacha.py` with the minified payload,
`--buf 32768 --limit 99999`.

## What was removed vs v7

- comments / DBG strings and RESULT plumbing (terser + manual dead-code removal)
- prototype-chain context fallback (CTXCHK)
- arena list-walk fallback: only the O(1) device arena path remains
  (`JSArenaGroup` at `rt+0x428`; worked on 72799/72879)
- ELF libc resolver: replaced by the fixed bionic delta
  `SYSTEM_DELTA = 0x26df0` (Sony Android 13 libc)

Kept: class-64 primitive, nonce/magic guards, O(1) arena runtime selection,
app PLT/GOT `js_free -> js_def_free -> free@plt -> GOT`, writer/reader,
command/hook, ChaCha+LZSS, PIN keypad.

## Trade-off

This is **not** the universal-libc v7. It is universal across Telegram builds
on a device whose bionic `free -> system` delta is 0x26df0. A libc table would
restore more coverage but needs a few hundred more compressed bytes; there are
only 154 B of margin with the keypad. The exact v7 stays the DB-only route.

Not yet device-tested after the reduction.

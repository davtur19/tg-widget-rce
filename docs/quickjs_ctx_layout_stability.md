# QuickJS object layout stability across Telegram Android betas

Date: 2026-11-05. Scope: arm64 Telegram Android widget sandbox, quickjs.
Question: can the context chain (`JSObject -> shape -> proto -> prop -> ctor
-> realm -> JSContext -> JSRuntime`) be treated as a fixed layout across app
versions, instead of carrying the arena fallback?

## Tested versions

| build | context path evidence | app constants |
|---|---|---|
| 72799 | v3 note uses `shape+48`, `proto+32`, `ctor+48`, `ctx+16` | `JS_DEF_FREE=0x173e36c`, `FREE_GOT=0x1964cc0` |
| 72879 | v7 ctx-only proofs 5465/5466; full marker `TRIG CTX` | `JS_DEF_FREE=0x174926c`, `FREE_GOT=0x196fef0` |

The **same five offsets** describe the chain in both builds:

```text
shape + 48   -> proto (JSObject*)
proto + 32   -> prop  (JSProperty*)
ctor  + 48   -> JSFunction realm = JSContext*
ctx   + 16   -> JSRuntime* rt
```

## What changed between 72799 and 72879

- The **app library build** changed: `JS_DEF_FREE` and `FREE_GOT` moved by
  ~0x10000. This is app code, not quickjs layout. The v7 payload removes both
  constants and decodes `js_def_free -> free@plt -> GOT` at runtime.
- The **allocator/arena layout** changed: on 72879 the arena O(1) path returned
  `rtArena = 0` (arena-only marker `ENT`), and the full payload selected
  `CTX` (marker `TRIG CTX`). No arena-only success has been observed on 72879.
- The **quickjs object layout used by the ctx chain stayed the same**:
  72799 (v3 note) and 72879 (v7 ctx-only) use identical offsets, and the
  ctx-only loader runs end-to-end on 72879 (proofs 5465, 5466).

## Other platforms / builds

- macOS beta 283434 / 283442: the `WidgetJS` bundles are byte-identical
  (`notes/macos_beta_283442_diff.md`); the object layout is expected to be the
  same, but no end-to-end macOS run was done.
- iOS: same widget sandbox/quickjs is expected; the endgame is different
  (Mach-O/dyld, libsystem, no `system()`), so the ctx chain alone is not a
  port.
- armv7 72799: the realm offset is `ctor + 0x18` (32-bit); the arm64 offsets
  do not apply.

## Decision

Treat the **ctx chain as a fixed layout** for the tested arm64 Telegram app
versions. This is a deliberate, documented assumption: the offsets are
quickjs-source-level and survived the 72799 -> 72879 app update, while the
allocator did not.

Keep runtime-universal only the parts that must be:

- app base / `js_def_free` / PLT / GOT discovery (no app-build constants);
- libc `free -> system` via the ELF resolver (no fixed libc delta);
- `system(CMD)` endgame and C2 outside the widget.

Do not rely on the arena as the primary path on 72879; it is dead weight
there. The full payload with arena + ctx still fits 4 KB (4,050 B zlib,
proofs 5463/5464), but the ctx-only payload is smaller (3,594 B zlib, 502 B
margin, proofs 5465/5466).

## If a future build changes the ctx layout

The five offsets are the only fixed part. On a new beta:

1. run the ctx-only loader with a marker; if it stops before `RT`, the layout
   changed;
2. update the five offsets from the new quickjs layout, or add a small offset
   table keyed by a build/quickjs fingerprint;
3. keep the runtime PLT/GOT and ELF resolver unchanged.

A table of 5 offsets per build is much smaller than restoring the arena path.

## Artifacts

- `poc/loader_v7_plain_text_ctxonly.html` — 3,594 B zlib, text "Ok", no
  keypad/encryption, auto-run, fixed ctx layout; proofs 5465/5466.
- `poc/loader_v7_plain_text_4k.html` — 4,050 B zlib, arena + ctx fallback;
  proofs 5463/5464.
- `notes/v7_plain_text_4k.md` — sizes and loader details.

## Update: GNU-hash-only resolver

The resolver now keeps only the GNU hash path (modern bionic). SysV hash and
the related dynamic tag are removed. Tested end-to-end: proof **5467**,
`exec rc=0 4.91s`, loader **3,518 B zlib** (578 B margin).

- artifact: `poc/loader_v7_plain_text_ctxonly_gnu.html`
- payload: `lab/regexp1827_class64/device_payload_v7_ctxonly_gnu.min.js`

The saving vs the both-hash ctx-only loader is small (76 B) because the SysV
branch compressed well. The remaining resolver cost is still the ELF base scan
+ dynamic symbols + GNU hash walk.

## Next universal-size options

1. **`dlsym` via an imported function pointer**: the app imports
   `dlsym`/`dlopen`/`dladdr`/`mprotect`. Replacing the ELF resolver with
   `dlsym(RTLD_DEFAULT, "system")` would save ~1 KB and stay libc-universal.
   Open question: calling it with controlled arguments from the class-64
   write primitive (likely via `rt->mf.js_realloc` and a controlled
   `ptr/size`), and capturing the return.
2. **Fix the arena for 72879**: the arena is the quickjs-layout-independent
   context path, but the 72879 allocator layout made `rtArena = 0`. Comparing
   the 72799 and 72879 `JSArenaGroup`/`JSMallocState` layouts in IDA would let
   the arena-only payload work; it is larger than the ctx chain but truly
   layout-independent. With the GNU resolver, arena-only is ~3.7 KB.
3. **Ctx offset table**: keep the fixed ctx chain as the small path and add a
   small table of the five offsets keyed by build/quickjs fingerprint for
   future versions. Not strictly universal, but much smaller than the arena.

Status 2026-11-05: the `dlsym` route is blocked. The only useful wrapper is
`0x1827988: mov x0,x1; mov x1,x2; b dlsym@plt`; there is no
`mov x0,xzr`/`eor`/`movz` + `b dlsym@plt` gadget, and the
`js_realloc(ptr=0, size=name)` trigger is not reachable from JS.

## Build profile policy (arm64, all Android versions)

Target: all Android arm64 devices, across Telegram builds. Test every new
Telegram version; do **not** chase universality across QuickJS/lib rewrites.
Pin only what is observed stable across tested builds; resolve everything
else at runtime.

### Current profile: `arm64-qjs-72799-72879`

Fixed (verified stable across 72799 -> 72879):

- ctx chain: `shape+48 -> proto`, `proto+32 -> prop`, `ctor+48 -> ctx`,
  `ctx+16 -> rt`, `rt+16 -> js_free`, `rt+64 -> opaque`;
- class 64, stride 64; `byte_length +0`, `max_byte_length +4`;
  class_id `+16` (29/30), `u.ptr +56`, `u.array.count +64`;
- `js_def_free` head `0xaa0103e0` (`mov x0,x1`) followed by `b free@plt`;
- fake libregexp header `b[2]=2, b[3]=3` (`capture_count=2`,
  `register_count=3`); `REOP_set_i32` with `pc=8j-4` -> `capture+64j`;
- `NW=8`, `NV=32`, `LIM=8192`, `FILL64=4000`, `FILL80=400`.

Runtime (never fixed):

- app/libc base, `js_def_free` address, PLT/GOT, `free`, `system`;
- heap addresses (`capture`, victims, `D`), MAGIC, all ASLR;
- GNU hash ELF resolver; no `SYSTEM_DELTA`.

Payload choices (not profile constants):

- `BN = 0x7a000000 + 8*0x12345`: fake `byte_length` immediate; range and
  8-alignment are what matter, the exact nonce is frozen for size;
- `CMD`, shell text, `nc`/`toybox nc` fallback.

### New-build procedure

1. Record version code/name, APK hash, `libtmessages.so` hash, QuickJS
   version and ABI.
2. Run the current 3,056 B loader on the new build; require a full C2 proof.
3. If it fails, run the DB-only full/debug v7 to see the stage (ctx, stub,
   resolver); compare the five ctx offsets and the stub pattern.
4. If only the five ctx offsets changed: update them; keep the rest.
5. If the fake bytecode header/opcode or the object layout changed:
   regenerate `mkbuf`/profile; do not try to keep the old profile universal.
6. If the `js_def_free` pattern changed (e.g. BTI/PAC): add a branch or select
   a new profile.
7. If #1827 is patched: stop; no payload works.
8. Add the build to the matrix and keep the old profile for old builds.

Matrix columns: build, APK/lib hash, QuickJS, ctx offsets, class/stride,
stub pattern, fake-bytecode header, loader size, proof, result.

### Android arm64 notes

- The profile is per APK/ABI, not per OS: the same Telegram build on Android
  7 and 13 uses the same QuickJS layout; the ELF resolver handles libc
  differences.
- Shell tools are stock AOSP: Android 7.1 has `/system/xbin/nc` (BSD nc) and
  toybox with `netcat`; Android 13 has `/system/bin/nc -> toybox` 0.8.6.
  `setsid`/`sleep` are toybox symlinks on both. No root/busybox required.
- Android 14/15 and Android 5/6 are still to verify; `nc`/`toybox nc` fallback
  costs ~40 B and the current margin is 1,040 B.
- x86/x86_64 are out of scope for this arm64 profile; armv7 is a separate
  profile (`ctor+0x18`, 32-bit stores, class 40).

## 2026-11-05 beta APK sweep

All ten beta APKs in `telegramandroidwidget/apks/` were inspected; all seven
13.2.0 builds pass with the same 3,056 B plaintext loader. Full details and
hashes: `notes/beta_apk_matrix_20261105.md`.

| versionCode | lib | proof |
|---:|---|---:|
| 72549 | 26,857,648 / `23b833a7…` | 5496 |
| 72559 | same lib, different sandbox bundle | 5499 |
| 72569 | same lib, same bundle as 72559 | 5500 |
| 72609 | `fed61e0f…` | 5497 |
| 72789 | `7d54541a…` | 5498 |
| 72799 | `1b756d81…` | 5503 |
| 72879 | `e83e517a…` | 5501/5502 (and 5489/5492/5493) |

13.1.1 (72499), 13.1.2 (72509/72539) have **no** `assets/WidgetSandbox`,
no `sandbox-bundle.qbc` and no `TL_messageMediaWidget`; the widget/QuickJS
attack surface does not exist there.

The only build-specific delta found is the DB message media constructor:

- 72549: old `messageMediaWidget#b7ed7b0d` (`width,height,payload`), old only;
- 72609+: new `#2238f214` (flags/width/height/payload + optional fields), with
  `_old`/`_layer233` compatibility classes. 72609/72789 accept the old media
  too, so the old-media fixture works from 72549 through 72789.

The QuickJS layout, ctx offsets, `js_def_free` pattern (`mov x0,x1; b
free@plt`), class-64 stride and fake-bytecode header were unchanged across
72549 -> 72879. No per-build loader change was needed.

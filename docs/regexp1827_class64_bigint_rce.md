# PR #1827 — class-64 ArrayBuffer `byte_length` → BigInt64 pivot → `system()`

> **2026-11-02 device update:** the device reached `VIEWS=6/7` but the
> class-13 `JSFunctionBytecode` ctx scan returned `NO_CTX`. The ctx step of
> this note is superseded by
> `notes/regexp1827_class64_v3_device_fix.md` (prototype-chain ctx + same-
> victim stable writer, one view is enough) and the device payloads are
> `device_payload_v3_*`. Keep this note for the class-64 primitive and the
> proof-file chain; do not re-test the class-13 variant.

Date: 2026-11-02. Target: Sony XQ-BT52, Android 13, `org.telegram.messenger.beta`
72799, quickjs-ng 7a23d8e (0.17.0 + JS_ReadBigInt). Scope: **host/lab only**
(the phone was not run for this note).

Status: **new full RCE chain, lab-validated end-to-end (proof file written,
5/5 + stress 5/5). Device payload emitted; device run pending.** This is not
#1865: the engine is the `JS_RegExpDelete` stale-bytecode UAF (PR #1827), and
the arbitrary write comes from the fake libregexp bytecode's `REOP_set_i32`.

Artifacts (all under `lab/regexp1827_class64/`):

| file | role |
|---|---|
| `device_payload_1827_class64.js` | **device payload** (FILL64=4000, F80=400, NV=32, NW=8, LIM=8192) |
| `device_payload_1827_class64_f2000.js` | low-memory variant (FILL64=2000) |
| `device_payload_1827_class64_f8000.js` | high-drain variant (FILL64=8000) |
| `gen_final.py` | template + device/lab constant emitter |
| `lab_final_v3.js` | lab twin (lab constants, proof `/tmp/opencode/...`) |
| `gen_stress_final.py` | lab stress (simulated fragmented class-64/80 free lists) |
| `evidence_lab.txt`, `evidence_stress.txt` | captured lab logs |

---

## 1. Why the old device blocker is bypassed

The previous attempt put the capture array in **class 80** (72 B capture, `cc=4
rc=1`) to overwrite a `Uint8Array` JSObject's `u.array.count`. On the phone the
class-80 free list is fragmented by the widget bundles (the measured
capture→`sv` delta was 21 blocks), so the count write missed the typed array.

The new primitive changes the **capture size class** instead of fighting the
class-80 list:

```
alloc_count = 2*capture_count + register_count
capture     = js_malloc(8 * alloc_count)      (after the lastIndex coercion)
```

`JS_RegExpDelete` sizes the capture array from the attacker-controlled fake
bytecode header (`bc_buf[2]`, `bc_buf[3]`). With `capture_count=2,
register_count=3`, `alloc_count=7` and the capture is a **56-byte request =
class-64 arena block**. Class 64 is the `JSArrayBuffer` struct slab (56 B
struct + 8 B header); in the release layout `JSShape` is class 80, so class 64
holds almost only `ArrayBuffer`/typed-array structs, a much smaller and
quieter free list than class 80.

`REOP_set_i32` writes `capture + 8*(2*capture_count + pc[0])`; with `cc=2`:

```
pc[0] = 8*j - 4   ->   offset 64*j   (j = 1..NW)
```

Offset 64*j is exactly the start of the j-th class-64 block after the capture
(block stride 64). The 8-byte store sets

```
struct+0: byte_length     = 0x7a000000 + 8*j     (positive, 8-aligned)
struct+4: max_byte_length = 0                    (>= 0 -> "resizable")
```

so the victim `ArrayBuffer` becomes a resizable buffer with a ~2 GB length and
its real data pointer. `new BigInt64Array(victim)` then yields
`count = byte_length/8 = 0x0f400000+j` with `u.array.u.ptr = data`, a huge
forward byte/word window, without touching any JSObject count field.

The capture block is the class-64 block freed by `tmpAb = new ArrayBuffer(16)`
just before the coercion returns; the victim structs are allocated immediately
after it, so with a drained class-64 list they are the next `NW` blocks.

## 2. The pivot (why the write is controlled)

A huge view alone is not enough on the phone: its JSObject is often *below*
its data block, and the huge-array window is forward-only. The payload
therefore gives every victim **two pads**, one allocated before and one after
its data block in the class-80 chain:

```
fns[i] fnA;  padA[i] {};  victim[i] ArrayBuffer(72);  padB[i] {};  fns[i] fnB
```

The victim data block `D` is a class-80 block. The class-80 chain step from
`D` to `padB` (and `padA` to `D`) has an unknown direction and distance, so
after the replace the payload:

1. frees `padA`, makes `va = new BigInt64Array(victim)` (class id **29**) — its
   JSObject reuses `padA`'s block;
2. frees `padB`, makes `vb = new BigUint64Array(victim)` (class id **30**) — its
   JSObject reuses `padB`'s block;
3. scans forward from `D` (`us = new Uint32Array(victim)`) for a JSObject with
   class 29/30 at `+18` and the victim's unique count at `+64`. Almost always
   one of the two pads is forward (whichever chain direction the arena uses);
   the class id tells the payload which JS reference owns the found block;
4. reads `u.ptr` at `J+56` -> `D`, then pivots the found view with a **single
   8-byte `BigInt64Array` store** at `D + k + 56` (`k = J - D`).

The single-store detail matters: writing the `u.ptr` field byte-by-byte would
change the view's own data pointer after the first byte and send the remaining
bytes to the wrong address. `BigInt64Array[i] = BigInt(addr)` performs one
8-byte store, so the pivot is atomic.

After the pivot the view's data pointer is an arbitrary absolute address and
`view[0]` reads/writes 8 bytes there. Six views drive the chain:

```
view A: pivot to fn->function_bytecode + 72   -> JSFunctionBytecode.realm = ctx
view B: pivot to ctx + 16                      -> JSRuntime *rt
view C: pivot to rt + 16                       -> rt->mf.js_free
view D: pivot to pieBase + free@GOT            -> libc free
view E: pivot to rt + 16, write system
view F: pivot to rt + 64, write command address
```

`JSFunctionBytecode.realm` is at +72 in the app layout (`mfunc` bytecode
header + bitfields + pointers, verified with a C layout probe). Any class-13
JSObject found forward of a view works: helper functions are allocated on both
sides of each victim, so the first hit is one of ours and its realm is the
sandbox `JSContext`.

`rt->mf.js_free = system` and `rt->malloc_state.opaque = cmd`, then a 4 KiB
typed-array free goes through `js_free_rt -> rt->mf.js_free(opaque, block) ->
system(cmd)`. The command is written into view E's 72-byte data buffer before
the pivot; `cmdAddr = E.D` is read from E's `u.ptr` field.

## 3. Lab evidence

Lab build: `lab/regexp1827_arena/build/lab_regexp_rel` (qjs017 + forced arena,
release layout). Current binary constants: `js_def_free=0x14520`,
`free@GOT=0x11afb0`, host `system-free=-0x4ff30`.

Final lab twin (`lab_final_v3.js`, FILL64=4000/F80=400/NV=32/NW=8/LIM=8192):

```
R1827:VIEWS=8 R1827:CTX R1827:HOOKED R1827:AFTER
proof: uid=1000(user) gid=1000(user) groups=...
```

5/5 consecutive runs wrote the proof (`evidence_lab.txt`).

Stress (simulated device fragmentation; `M64` live `ArrayBuffer(16)` junk freed
every 3rd, `M80` 47-char strings freed every 3rd):

| FILL64 | M64 | M80 | result |
|---|---|---|---|
| 4000 | 5000 | 30000 | VIEWS=8 CTX HOOKED AFTER, proof |
| 4000 | 5000 | 30000 | same |
| 2000 | 5000 | 30000 | VIEWS=8 CTX HOOKED AFTER, proof |
| 4000 | 1000 | 50000 | VIEWS=8 CTX HOOKED AFTER, proof |
| 4000 | 10000 | 10000 | VIEWS=8 CTX HOOKED AFTER, proof |

`M80=30000` is ~10k free class-80 blocks (the phone measured a fragmented
class-80 list); it does not matter because the dual pads do not require
class-80 defragmentation. `M64=5000` is ~1667 free class-64 structs; FILL64
must exceed this, and 2000 did.

Timing on the host: final payload ~30-35 ms process time (empty script 5 ms);
`new ArrayBuffer(16)` x 4000/8000/16000 costs ~14/17/20 ms inside the script.
The widget budget is 300 ms CPU (`cpuQuotaMs=300`), so the filler count is not
expected to exhaust it; the device number is unmeasured.

## 4. Device procedure

1. Inject `device_payload_1827_class64.js` as one synchronous widget script
   (same path as the previous #1827 payloads; 8 MiB JS limit, no timers).
2. Read the markers from the widget log / `globalThis.RESULT`:
   `R1827:VIEWS=...`, `R1827:CTX`, `R1827:HOOKED`, `R1827:AFTER`.
3. Read the proof:
   `adb shell run-as org.telegram.messenger.beta cat cache/rce_proof`
   (or `su -c cat /data/user/0/org.telegram.messenger.beta/cache/rce_proof`).
   Success = `uid=...(...)` with the app UID.
4. A crash after `AFTER` (or after `HOOKED`) is acceptable: the command runs at
   the first large free; the allocator hook is destructive and teardown may
   follow. The proof file is written by `system()` before that.

Markers and actions:

| marker | meaning / action |
|---|---|
| `EXC_REPLACE` | fake bytecode did not execute (454-byte reclaim/header); do not retry blindly |
| `VIEWS=0..5` | fewer than 6 usable pivots: class-64 drain insufficient or the write missed the victims; try `_f8000` (or `_f2000` if memory is tight) |
| `NO_CTX` | views exist but no class-13 JSObject/realm forward of a view; try a different FILL64/F80 phase or raise LIM |
| `NO_RT` / `NO_FREE` | ctx/rt/js_free read failed (tagged pointer check, wrong layout); report the marker |
| `NO_SYS` | wrapper and direct-libc `system` both failed; the `JS_DEF_FREE`/`FREE_GOT`/`SYSTEM_DELTA` constants do not match the build |
| `HOOKED` | `rt+16`/`rt+64` written; trigger follows |
| `AFTER` | the large free returned; check the proof file |

Device constants in the payload: `JS_DEF_FREE=0x1739aec`,
`FREE_GOT=0x1960430`, `SYSTEM_DELTA=+0x26df0` (the values from the parent
session's app-72799 analysis). If `js_free` is libc `free` directly (bionic may
merge the wrapper), the payload falls back to `system = js_free + delta`.

## 5. Risks and the exact remaining blockers

1. **Class-64 free-list size.** The one-shot victim run needs `FILL64` live
   `ArrayBuffer(16)` structs to drain the class-64 list, so that
   `tmpAb`+victims are chain-consecutive. Class 64 contains only
   `JSArrayBuffer` structs in this release layout (shapes are class 80), so it
   should be small, but the phone number is unmeasured. `_f2000` is the safe
   memory point; `_f8000` is the high-drain point. If `_f4000` gives
   `VIEWS=0` without crashing, try `_f8000`; if it crashes during the replace,
   the class-64 list is larger than the chosen filler count.
2. **Class-64 arena-boundary phase.** `tmpAb` + 8 victims is a 9-block run in a
   63-block class-64 arena. If the run crosses an arena boundary, the Scudo
   primary packs 4112-byte chunks, so the `+64*j` grid is shifted by 16 bytes
   in the next arena; the write lands at struct+48 (`realloc_func`) instead of
   `byte_length`. That is harmless until teardown (the victim is not freed
   before the command), but the crossed victim is not usable. The dual-pad
   scan tolerates fewer than 8 corrupted victims as long as 6 survive.
3. **Class-80 chain direction/distance.** The pads are one chain step from `D`;
   the scan is limited to 8 KiB. The device's measured #1827 chain steps were
   1680-1784 B, well inside. If the free list jumps farther, `NO_CTX` /
   `VIEWS<6`; raising `LIM` to 16384 is the next knob.
4. **Pointer tagging (MTE/TBI).** `plausible()` masks the top byte of data
   pointers; tagged `ctx`/`rt` values are preserved through the pivots and are
   dereferenced with the tag from the pointer itself. Code pointers
   (`js_free`, `free`, `system`) are checked 4-byte aligned and untagged.
5. **Constants.** The `JS_DEF_FREE`/`FREE_GOT`/`SYSTEM_DELTA` values are the
   only version-specific data. `NO_SYS` means they do not match the running
   libtmessages; the chain has already proven the arbitrary read/write by then.

## 6. Why this is a new RCE, not #1865

The engine is the #1827 UAF: `JS_RegExpDelete` snapshots `re->bytecode` before
the `lastIndex` coercion, the coercion `re.compile('x')` frees the 454-byte
libregexp DynBuf, `new Uint8Array(454)` reclaims it, and the fake program's
`REOP_set_i32` performs the writes. No generator frame, no `var_refs` OOB, no
`Array.prototype.find` interrupt UAF is used. The arbitrary R/W comes from a
real `BigInt64Array` whose `u.ptr` is pivoted by a single 8-byte store; the
final `system()` is reached by the allocator hook `rt->mf.js_free`.

